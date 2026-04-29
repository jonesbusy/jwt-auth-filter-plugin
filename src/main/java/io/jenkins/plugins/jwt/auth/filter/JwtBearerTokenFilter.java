package io.jenkins.plugins.jwt.auth.filter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import hudson.Extension;
import hudson.model.User;
import hudson.tasks.Mailer;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import jenkins.util.HttpServletFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The request filter that validate JWT given as Bearer token
 */
@Extension
public class JwtBearerTokenFilter implements HttpServletFilter {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenFilter.class);

    public static final String BEARER_PREFIX = "Bearer ";
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;

    @Override
    public boolean handle(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws IOException, ServletException {

        String requestURI = httpRequest.getRequestURI();

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (!config.anyMatch(config.getProtectedPaths(), requestURI)) {
            LOG.trace("Request URI '{}' does not match protected paths - skipping JWT filter", requestURI);
            return false;
        }

        // Check if this is an API request with Bearer token
        // If not, just continue the filters
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return false;
        }

        LOG.trace("Processing JWT Bearer token for: {}", requestURI);

        // Extract and validate JWT token
        String token = authHeader.substring(BEARER_PREFIX.length());
        boolean skipJwtValidation =
                Boolean.TRUE.equals(httpRequest.getAttribute(JwtBearerTokenCrumbExclusion.class.getName()));
        Authentication authentication = validateJwtToken(skipJwtValidation, token);

        if (authentication != null) {

            // Set authentication context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            LOG.info("JWT Bearer token authenticated user '{}' at path '{}'", authentication.getName(), requestURI);
            return false; // Continue filter chain
        }

        // Continue filters
        LOG.debug("JWT Bearer token validation failed - continuing with normal auth");
        return false;
    }

    /**
     * Verifies the signature of a signed JWT using JWKS.
     */
    public static boolean verifyJwtSignature(SignedJWT signedJWT) {
        try {
            JWSHeader header = signedJWT.getHeader();
            String keyId = header.getKeyID();

            // Get the JWK
            JWK jwk = getJwkForVerification(keyId);
            if (jwk == null) {
                LOG.debug("No JWK found for key ID: {}", keyId);
                return false;
            }

            // Reject expired token
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                LOG.debug("JWT token has expired: {}", expirationTime);
                return false;
            }

            // Validate issued at time (with clock skew tolerance)
            Date issuedAt = claimsSet.getIssueTime();
            if (issuedAt != null) {
                long clockSkewMillis = DEFAULT_CLOCK_SKEW_SECONDS * 1000;
                Date now = new Date();
                if (issuedAt.getTime() > now.getTime() + clockSkewMillis) {
                    LOG.debug(
                            "JWT token issued in the future (allowed clock skew: {}s): {}",
                            DEFAULT_CLOCK_SKEW_SECONDS,
                            issuedAt);
                    return false;
                }
            }

            // Verify signature
            JWSVerifier verifier = createVerifier(jwk);
            return signedJWT.verify(verifier);

        } catch (Exception e) {
            LOG.warn("JWT signature verification error", e);
            return false;
        }
    }

    /**
     * Gets the appropriate JWK for verification from JWKS.
     */
    private static JWK getJwkForVerification(String keyId) {
        try {
            JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
            String jwksUrl = config != null ? config.getJwksUrl() : null;

            if (jwksUrl == null || jwksUrl.trim().isEmpty()) {
                LOG.warn("JWKS URL not configured. Please configure it in Jenkins Global Configuration.");
                return null;
            }

            JWKSet jwkSet = getJwks(jwksUrl);
            if (jwkSet == null) {
                LOG.warn("Failed to fetch JWKS from: {}", jwksUrl);
                return null;
            }
            LOG.debug(
                    "JWKS fetched successfully, contains {} keys",
                    jwkSet.getKeys().size());

            // Find key by ID or use first available key
            JWK jwk = null;
            if (keyId != null) {
                LOG.debug("Looking for key with ID: {}", keyId);
                jwk = jwkSet.getKeyByKeyId(keyId);
                if (jwk != null) {
                    LOG.debug("Found key with matching ID: {}", keyId);
                } else {
                    LOG.debug("No key found with ID: {}", keyId);
                }
            }

            if (jwk == null && !jwkSet.getKeys().isEmpty()) {
                // If no key ID specified or key not found, try the first key
                jwk = jwkSet.getKeys().get(0);
                LOG.debug("Using first available JWK for verification");
            }

            return jwk;

        } catch (Exception e) {
            LOG.warn("Failed to get JWK for verification", e);
            return null;
        }
    }

    /**
     * Gets the JWK set
     */
    private static JWKSet getJwks(String url) {
        try {
            LOG.debug("Fetching JWKS from: {}", url);
            return JWKSet.load(new URL(url));
        } catch (IOException | ParseException e) {
            LOG.debug("Failed to fetch JWKS from: {}", url, e);
            return null;
        }
    }

    /**
     * Creates appropriate JWS verifier based on key type and algorithm.
     */
    private static JWSVerifier createVerifier(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey rsaKey) {
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            return new RSASSAVerifier(publicKey);
        } else if (jwk instanceof ECKey ecKey) {
            ECPublicKey publicKey = ecKey.toECPublicKey();
            return new ECDSAVerifier(publicKey);

        } else if (jwk instanceof OctetSequenceKey hsKey) {
            byte[] secretKey = hsKey.toByteArray();
            return new MACVerifier(secretKey);

        } else {
            LOG.debug("Unsupported JWK type: {}", jwk.getClass().getName());
            throw new IllegalArgumentException(
                    "Unsupported JWK type: " + jwk.getClass().getName());
        }
    }

    /**
     * Validates JWT token and returns Authentication object if valid.
     */
    private Authentication validateJwtToken(boolean skipJwtValidation, String tokenString) {
        try {
            LOG.debug("Starting JWT token validation");

            // Parse JWT token
            SignedJWT signedJWT = SignedJWT.parse(tokenString);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            LOG.debug(
                    "JWT parsed successfully. Subject: {}, Issuer: {}", claimsSet.getSubject(), claimsSet.getIssuer());

            if (skipJwtValidation) {
                LOG.info("Skipping JWT signature validation due to request attribute from crumb");
            } else {
                LOG.info("Performing JWT signature validation");
            }

            // Validate token signature
            if (!skipJwtValidation && !verifyJwtSignature(signedJWT)) {
                LOG.warn("JWT token signature validation failed");
                return null;
            }

            // Validate claims (expiration, audience, issuer)
            if (!validateTokenClaims(claimsSet)) {
                LOG.debug("JWT token claims validation failed");
                return null;
            }

            // Extract user information
            String username = extractUsername(claimsSet);
            if (username == null || username.isEmpty()) {
                LOG.warn("Unable to extract username from JWT token");
                return null;
            }
            String name = extractName(claimsSet);
            String email = extractEmail(claimsSet);

            // Extract authorities/groups
            Collection<GrantedAuthority> authorities = extractAuthorities(claimsSet);
            LOG.debug("Extracted username: {} with {} authorities", username, authorities.size());

            // Create or update Jenkins user
            ensureUserExists(username, name, email);

            LOG.debug("JWT validation completed successfully for user: {}", username);
            return new JwtBearerTokenAuthentication(username, authorities);

        } catch (ParseException e) {
            LOG.warn("Failed to parse JWT token", e);
            return null;
        } catch (Exception e) {
            LOG.warn("JWT token validation error", e);
            return null;
        }
    }

    /**
     * Validates JWT token claims (expiration, audience, etc.).
     */
    private boolean validateTokenClaims(JWTClaimsSet claimsSet) {
        try {

            // Validate audience
            JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
            String expectedAudience = config != null ? config.getAllowedAudience() : null;

            if (expectedAudience == null || expectedAudience.trim().isEmpty()) {
                LOG.warn("Allowed audience not configured. Please configure it in Jenkins Global Configuration.");
                return false;
            }

            List<String> audiences = claimsSet.getAudience();
            if (audiences == null || !audiences.contains(expectedAudience)) {
                LOG.warn("JWT token audience validation failed - Expected: {}, Found: {}", expectedAudience, audiences);
                return false;
            }
            return true;

        } catch (Exception e) {
            LOG.warn("JWT claims validation failed with exception", e);
            return false;
        }
    }

    /**
     * Extracts username from JWT claims using OIDC realm configuration.
     */
    private String extractUsername(JWTClaimsSet claimsSet) {
        try {
            Object username = claimsSet.getClaim("preferred_username");
            return username != null ? username.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract preferred_username from JWT", e);
            return null;
        }
    }

    /**
     * Extracts username from JWT claims using OIDC realm configuration.
     */
    private String extractEmail(JWTClaimsSet claimsSet) {
        try {
            Object email = claimsSet.getClaim("email");
            return email != null ? email.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract email from JWT", e);
            return null;
        }
    }

    /**
     * Extracts name from JWT claims using OIDC realm configuration.
     */
    private String extractName(JWTClaimsSet claimsSet) {
        try {
            Object username = claimsSet.getClaim("name");
            return username != null ? username.toString() : null;
        } catch (Exception e) {
            LOG.debug("Failed to extract name from JWT", e);
            return null;
        }
    }

    /**
     * Extracts authorities/groups from JWT claims using OIDC realm configuration.
     */
    private Collection<GrantedAuthority> extractAuthorities(JWTClaimsSet claimsSet) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        try {
            // Get groups
            Object groupsClaim = claimsSet.getClaim("groups");
            @SuppressWarnings("unchecked")
            List<String> groups = (List<String>) groupsClaim;
            authorities.addAll(groups.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));

            // Always add authenticated authority
            authorities.add(new SimpleGrantedAuthority("authenticated"));

        } catch (Exception e) {
            LOG.debug("Failed to extract authorities from JWT", e);
        }

        return authorities;
    }

    /**
     * Ensures the user exists in Jenkins user database.
     */
    private void ensureUserExists(String username, String name, String email) {
        try {
            User user = User.getById(username, true);
            if (user != null) {
                updateUserProperties(user, name, email);
            }
        } catch (Exception e) {
            LOG.debug("Failed to create/update user: {}", username, e);
        }
    }

    /**
     * Updates user properties from JWT claims.
     */
    private void updateUserProperties(User user, String name, String email) {
        try {
            if (email != null && !email.trim().isEmpty()) {
                user.addProperty(new Mailer.UserProperty(email));
            }
            if (name != null && !name.trim().isEmpty()) {
                user.setFullName(name);
            }
            user.save();
        } catch (Exception e) {
            LOG.debug("Failed to update user properties", e);
        }
    }
}
