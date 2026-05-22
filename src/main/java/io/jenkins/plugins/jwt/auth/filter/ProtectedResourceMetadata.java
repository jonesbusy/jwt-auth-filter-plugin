package io.jenkins.plugins.jwt.auth.filter;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class ProtectedResourceMetadata extends AbstractDescribableImpl<ProtectedResourceMetadata> {

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
        return scopesSupported != null ? new ArrayList<>(scopesSupported) : new ArrayList<>();
    }

    public String getScopesSupportedValue() {
        return String.join(",", getScopesSupported());
    }

    @DataBoundSetter
    public void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported != null ? new ArrayList<>(scopesSupported) : new ArrayList<>();
    }

    @DataBoundSetter
    public void setScopesSupportedValue(String scopesSupportedValue) {
        if (scopesSupportedValue == null || scopesSupportedValue.isBlank()) {
            this.scopesSupported = new ArrayList<>();
            return;
        }
        this.scopesSupported = Arrays.stream(scopesSupportedValue.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toCollection(ArrayList::new));
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<ProtectedResourceMetadata> {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Protected Resource";
        }
    }
}
