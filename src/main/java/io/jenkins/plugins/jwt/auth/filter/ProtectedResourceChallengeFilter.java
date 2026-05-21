package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import jenkins.util.HttpServletFilter;

@Extension
public class ProtectedResourceChallengeFilter implements HttpServletFilter {

    @Override
    public boolean handle(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws IOException, ServletException {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (config == null || !config.isProtectedResourceMetadataEnabled()) {
            return false;
        }

        if (!config.isProtectedResource(httpRequest.getRequestURI(), httpRequest.getContextPath())) {
            return false;
        }

        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX)) {
            return false;
        }

        String metadataUrl = config.getProtectedResourceMetadataUrl();
        if (metadataUrl == null || metadataUrl.isBlank() || metadataUrl.contains("\r") || metadataUrl.contains("\n")) {
            return false;
        }
        httpResponse.setHeader("WWW-Authenticate", "Bearer resource_metadata=\"" + metadataUrl + "\"");
        return false;
    }
}
