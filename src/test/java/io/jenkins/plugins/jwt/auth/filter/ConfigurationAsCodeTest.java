package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.*;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import java.util.List;
import org.junit.jupiter.api.Test;

@WithJenkinsConfiguredWithCode
class ConfigurationAsCodeTest {

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    void shouldSupportConfigurationAsCode(JenkinsConfiguredWithCodeRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        assertNotNull(config, "Configuration instance should not be null");

        List<Issuer> issuers = config.getIssuers();
        assertNotNull(issuers, "Issuers should not be null");
        assertEquals(2, issuers.size(), "Should have 2 issuers from configuration-as-code.yml");

        // Verify first issuer
        Issuer issuer1 = issuers.get(0);
        assertEquals(
                "https://keycloak-casc-test.example.com/realms/jenkins/protocol/openid-connect/certs",
                issuer1.getJwksUrl(),
                "First issuer JWKS URL should be loaded from configuration-as-code.yml");
        assertEquals(
                "jenkins-casc-test2",
                issuer1.getAllowedAudience(),
                "First issuer allowed audience should be loaded from configuration-as-code.yml");
        assertEquals(
                "/mcp/**",
                issuer1.getProtectedPaths(),
                "First issuer protected paths should be loaded from configuration-as-code.yml");

        // Verify second issuer
        Issuer issuer2 = issuers.get(1);
        assertEquals(
                "https://keycloak-casc-test.other.com/realms/jenkins/protocol/openid-connect/certs",
                issuer2.getJwksUrl(),
                "Second issuer JWKS URL should be loaded from configuration-as-code.yml");
        assertEquals(
                "jenkins-casc-test2",
                issuer2.getAllowedAudience(),
                "Second issuer allowed audience should be loaded from configuration-as-code.yml");
        assertEquals(
                "/**/api/**",
                issuer2.getProtectedPaths(),
                "Second issuer protected paths should be loaded from configuration-as-code.yml");
    }
}
