package io.jenkins.plugins.jwt.auth.filter;

import com.nimbusds.jwt.SignedJWT;
import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JWT bearer token that exclude requested from Crumb that contains a valid signed JWT token
 */
@Extension
public class JwtBearerTokenCrumbExclusion extends CrumbExclusion {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenCrumbExclusion.class);

    @Override
    public boolean process(HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain chain)
            throws IOException, ServletException {

        // Skip if not on configured path
        String requestURI = httpRequest.getRequestURI();
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (!config.anyMatch(config.getProtectedPaths(), requestURI)) {
            LOG.trace("Request URI '{}' does not match protected paths - skipping JWT Bearer Crumb filter", requestURI);
            return false;
        }

        // Skip if header is missing
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX)) {
            chain.doFilter(httpRequest, httpResponse);
            return false;
        }

        // Validate a valid JWT token
        String tokenString = authHeader.substring(JwtBearerTokenFilter.BEARER_PREFIX.length());
        try {
            if (JwtBearerTokenFilter.verifyJwtSignature(SignedJWT.parse(tokenString))) {
                LOG.info("Valid JWT token found in request, excluding from Crumb");
                httpRequest.setAttribute(JwtBearerTokenCrumbExclusion.class.getName(), Boolean.TRUE);
                chain.doFilter(httpRequest, httpResponse);
                return true;
            }
        } catch (Exception e) {
            // Do nothing
        }
        chain.doFilter(httpRequest, httpResponse);
        return false;
    }
}
