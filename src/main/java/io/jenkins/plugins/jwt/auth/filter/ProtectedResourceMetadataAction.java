package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import java.util.List;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;

@Extension
public class ProtectedResourceMetadataAction implements UnprotectedRootAction {

    static final String WELL_KNOWN_PATH = ".well-known/oauth-protected-resource";

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return WELL_KNOWN_PATH;
    }

    public HttpResponse doIndex() {
        return metadataResponseFor("/");
    }

    public HttpResponse doDynamic(StaplerRequest2 request) {
        return metadataResponseFor(request.getRestOfPath());
    }

    private HttpResponse metadataResponseFor(String wellKnownPath) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (config == null || !config.isProtectedResourceMetadataEnabled()) {
            return HttpResponses.notFound();
        }

        ProtectedResourceMetadata protectedResourceMetadata =
                config.getProtectedResourceMetadataForWellKnownPath(wellKnownPath);
        if (protectedResourceMetadata == null) {
            return HttpResponses.notFound();
        }

        String resource = config.getEffectiveResource(protectedResourceMetadata);
        if (resource == null || resource.isBlank()) {
            return HttpResponses.errorJSON("resource is not configured and Jenkins root URL is unavailable");
        }

        String authorizationServer = protectedResourceMetadata.getAuthorizationServer();
        if (authorizationServer == null || authorizationServer.isBlank()) {
            return HttpResponses.notFound();
        }

        JSONObject metadata = new JSONObject();
        metadata.put("resource", resource);
        metadata.put("authorization_servers", List.of(authorizationServer.trim()));
        List<String> scopesSupported = protectedResourceMetadata.getScopesSupported();
        if (!scopesSupported.isEmpty()) {
            metadata.put("scopes_supported", scopesSupported);
        }
        return HttpResponses.okJSON(metadata);
    }
}
