package io.jenkins.plugins.jwt.auth.filter;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.util.HttpResponses;
import java.util.List;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;

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
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        if (config == null || !config.isProtectedResourceMetadataEnabled()) {
            return HttpResponses.notFound();
        }

        String resource = config.getEffectiveResource();
        if (resource == null || resource.isBlank()) {
            return HttpResponses.errorJSON("resource is not configured and Jenkins root URL is unavailable");
        }

        JSONObject metadata = new JSONObject();
        metadata.put("resource", resource);
        metadata.put("authorization_servers", List.of(config.getAuthorizationServer()));
        List<String> scopesSupported = config.getScopesSupported();
        if (!scopesSupported.isEmpty()) {
            metadata.put("scopes_supported", scopesSupported);
        }
        return HttpResponses.okJSON(metadata);
    }
}
