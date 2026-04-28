package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.*;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import org.junit.jupiter.api.Test;

@WithJenkinsConfiguredWithCode
class ConfigurationAsCodeTest {

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    void shouldSupportConfigurationAsCode(JenkinsConfiguredWithCodeRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        assertNotNull(config, "Configuration instance should not be null");
        assertEquals(
                "https://keycloak-casc-test.example.com/realms/jenkins/protocol/openid-connect/certs",
                config.getJwksUrl(),
                "JWKS URL should be loaded from configuration-as-code.yml");
        assertEquals(
                "jenkins-casc-test",
                config.getAllowedAudience(),
                "Allowed audience should be loaded from configuration-as-code.yml");
        assertEquals(
                "/**/api/**,/mcp/**",
                config.getProtectedPaths(),
                "Protected paths should be loaded from configuration-as-code.yml");
    }
}
