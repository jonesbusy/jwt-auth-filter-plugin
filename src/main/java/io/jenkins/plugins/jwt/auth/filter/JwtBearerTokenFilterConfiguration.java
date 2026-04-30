package io.jenkins.plugins.jwt.auth.filter;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.verb.POST;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

/**
 * Global configuration for JWT Bearer Token authentication plugin.
 */
@Extension
@Symbol("jwtBearer")
public class JwtBearerTokenFilterConfiguration extends GlobalConfiguration {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(JwtBearerTokenFilterConfiguration.class);

    private List<Issuer> issuers;
    private static final AntPathMatcher ANT_MATCHER = new AntPathMatcher();
    private static final String PATH_SEPARATOR = ",";

    @DataBoundConstructor
    public JwtBearerTokenFilterConfiguration() {
        load();
    }

    public static JwtBearerTokenFilterConfiguration getInstance() {
        return GlobalConfiguration.all().get(JwtBearerTokenFilterConfiguration.class);
    }

    @Override
    public @NonNull String getDisplayName() {
        return "JWT Bearer Token Authentication";
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    public List<Issuer> getIssuers() {
        return issuers != null ? issuers : new ArrayList<>();
    }

    @DataBoundSetter
    public void setIssuers(List<Issuer> issuers) {
        this.issuers = issuers != null ? new ArrayList<>(issuers) : new ArrayList<>();
    }

    @Override
    public @NonNull GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    /**
     * Returns the first issuer that matches the request URI path patterns.
     * @param requestURI The request URI
     * @return The matching issuer, or null if none matches
     */
    public Issuer getMatchingIssuer(String requestURI) {
        if (issuers == null || issuers.isEmpty()) {
            return null;
        }
        return issuers.stream()
                .filter(issuer -> issuer.matchesPath(requestURI))
                .findFirst()
                .orElse(null);
    }

    /**
     * Return if the request URI match any of the protected path patterns from any issuer
     * @param requestURI The request URI
     * @return True if the URI matches any protected path pattern, false otherwise
     */
    public boolean anyMatch(String requestURI) {
        if (issuers == null || issuers.isEmpty()) {
            return false;
        }
        return issuers.stream().anyMatch(issuer -> issuer.matchesPath(requestURI));
    }

    // Deprecated methods for backward compatibility - these are no longer used but kept for potential legacy code
    @Deprecated
    boolean anyMatch(String protectedPaths, String requestURI) {
        if (protectedPaths == null) {
            return false;
        }
        return Arrays.stream(protectedPaths.split(PATH_SEPARATOR)).anyMatch(pattern -> {
            boolean result = ANT_MATCHER.match(pattern.trim(), requestURI.trim());
            LOG.trace("Matching pattern: '{}' with '{}' with result '{}'", pattern, requestURI, result);
            return result;
        });
    }

    @POST
    @SuppressWarnings("unused")
    public FormValidation doTestPath(@QueryParameter String protectedPaths, @QueryParameter String testPath) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        LOG.trace("Testing path '{}' against protected paths pattern '{}'", testPath, protectedPaths);
        if (protectedPaths == null) {
            return FormValidation.error("Protected path cannot be empty.");
        }
        boolean matches = Arrays.stream(protectedPaths.split(PATH_SEPARATOR)).anyMatch(pattern -> {
            return ANT_MATCHER.match(pattern.trim(), testPath.trim());
        });
        if (matches) {
            return FormValidation.ok("The test path matches at least one of the protected paths pattern.");
        }
        return FormValidation.error("The test path does NOT match any of the protected paths pattern.");
    }
}
