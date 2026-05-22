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

        ProtectedResourceMetadata protectedResource =
                config.findProtectedResource(httpRequest.getRequestURI(), httpRequest.getContextPath());
        if (protectedResource == null) {
            return false;
        }

        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith(JwtBearerTokenFilter.BEARER_PREFIX)) {
            return false;
        }

        String metadataUrl = config.getProtectedResourceMetadataUrl(protectedResource);
        if (metadataUrl != null
                && !metadataUrl.isBlank()
                && !metadataUrl.contains("\r")
                && !metadataUrl.contains("\n")) {
            httpResponse.setHeader("WWW-Authenticate", "Bearer resource_metadata=\"" + metadataUrl + "\"");
        }
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse
                .getWriter()
                .write("{\"error\":\"unauthorized\",\"error_description\":\"Authentication required\"}");
        return true;
    }
}
