package io.jenkins.plugins.jwt.auth.filter;

import com.nimbusds.jose.jwk.JWKSet;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

/**
 * Represents a single JWT issuer configuration with its JWKS URL, allowed audience, and protected paths.
 */
public class Issuer implements Describable<Issuer> {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(Issuer.class);

    private static final AntPathMatcher ANT_MATCHER = new AntPathMatcher();
    private static final String PATH_SEPARATOR = ",";

    private String jwksUrl;
    private String allowedAudience;
    private String protectedPaths;

    @DataBoundConstructor
    public Issuer() {}

    Issuer(String jwksUrl, String allowedAudience, String protectedPaths) {
        this.jwksUrl = jwksUrl;
        this.allowedAudience = allowedAudience;
        this.protectedPaths = protectedPaths;
    }

    public String getJwksUrl() {
        return jwksUrl;
    }

    @DataBoundSetter
    public void setJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    public String getAllowedAudience() {
        return allowedAudience;
    }

    @DataBoundSetter
    public void setAllowedAudience(String allowedAudience) {
        this.allowedAudience = allowedAudience;
    }

    public String getProtectedPaths() {
        return protectedPaths;
    }

    @DataBoundSetter
    public void setProtectedPaths(String protectedPaths) {
        this.protectedPaths = protectedPaths;
    }

    /**
     * Return if the request URI matches any of the protected path patterns for this issuer.
     * @param requestURI The request URI
     * @return True if the URI matches any protected path pattern, false otherwise
     */
    public boolean matchesPath(String requestURI) {
        if (protectedPaths == null) {
            return false;
        }
        return Arrays.stream(protectedPaths.split(PATH_SEPARATOR)).anyMatch(pattern -> {
            boolean result = ANT_MATCHER.match(pattern.trim(), requestURI.trim());
            LOG.trace("Matching pattern: '{}' with '{}' with result '{}'", pattern, requestURI, result);
            return result;
        });
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<Issuer> {

        @NonNull
        @Override
        public String getDisplayName() {
            return "JWT Issuer";
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doTestPath(@QueryParameter String protectedPaths, @QueryParameter String testPath) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            LOG.trace("Testing path '{}' against protected paths pattern '{}'", testPath, protectedPaths);
            if (protectedPaths == null) {
                return FormValidation.error("Protected path cannot be empty.");
            }
            boolean matches = Arrays.stream(protectedPaths.split(PATH_SEPARATOR))
                    .anyMatch(pattern -> ANT_MATCHER.match(pattern.trim(), testPath.trim()));
            if (matches) {
                return FormValidation.ok("The test path matches at least one of the protected paths pattern.");
            }
            return FormValidation.error("The test path does NOT match any of the protected paths pattern.");
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckProtectedPaths(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Protected path cannot be empty.");
            }
            String[] parts = value.split(PATH_SEPARATOR);
            for (String part : parts) {
                if (part == null || part.trim().isEmpty()) {
                    return FormValidation.error("Protected path cannot be empty.");
                }
                if (!ANT_MATCHER.isPattern(part.trim())) {
                    return FormValidation.error(
                            "Invalid Ant-style pattern: '" + part.trim() + "'. Please provide a valid pattern.");
                }
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckJwksUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error(
                        "JWKS URL cannot be empty. Please provide a valid URL to fetch the JWKS from.");
            }

            String trimmedValue = value.trim();

            // Basic URL format validation
            try {
                new URL(trimmedValue);
            } catch (MalformedURLException e) {
                return FormValidation.error("Invalid URL format: " + e.getMessage());
            }

            // Attempt to fetch and validate JWKS
            try {
                JWKSet jwkSet = JWKSet.load(new URL(trimmedValue));
                if (jwkSet.getKeys().isEmpty()) {
                    return FormValidation.warning(
                            "JWKS endpoint is reachable but contains no keys. Make sure this is the correct endpoint.");
                }
                return FormValidation.ok(
                        "Successfully fetched JWKS with " + jwkSet.getKeys().size() + " key(s)");
            } catch (IOException e) {
                return FormValidation.error("Failed to fetch JWKS from URL: " + e.getMessage()
                        + ". Please check the URL and ensure Jenkins can reach the endpoint.");
            } catch (ParseException e) {
                return FormValidation.error("Invalid JWKS format returned from URL: " + e.getMessage()
                        + ". Please verify this is a valid JWKS endpoint.");
            } catch (Exception e) {
                return FormValidation.error("Unexpected error while validating JWKS URL: " + e.getMessage());
            }
        }

        @POST
        @SuppressWarnings("unused")
        public FormValidation doCheckAllowedAudience(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Allowed audience cannot be empty.");
            }
            return FormValidation.ok();
        }
    }
}
