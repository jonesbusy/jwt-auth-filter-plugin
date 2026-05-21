package io.jenkins.plugins.jwt.auth.filter;

import java.util.ArrayList;
import java.util.List;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class ProtectedResourceMetadata {

    private String path;
    private String authorizationServer;
    private String resource;
    private List<String> scopesSupported;

    @DataBoundConstructor
    public ProtectedResourceMetadata(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    @DataBoundSetter
    public void setPath(String path) {
        this.path = path;
    }

    public String getAuthorizationServer() {
        return authorizationServer;
    }

    @DataBoundSetter
    public void setAuthorizationServer(String authorizationServer) {
        this.authorizationServer = authorizationServer;
    }

    public String getResource() {
        return resource;
    }

    @DataBoundSetter
    public void setResource(String resource) {
        this.resource = resource;
    }

    public List<String> getScopesSupported() {
        return scopesSupported != null ? scopesSupported : new ArrayList<>();
    }

    @DataBoundSetter
    public void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported != null ? new ArrayList<>(scopesSupported) : new ArrayList<>();
    }
}
