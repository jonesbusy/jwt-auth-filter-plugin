package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Tests for JWT Bearer Token Filter Configuration roundtrip functionality.
 */
@WithJenkins
class JwtBearerTokenFilterConfigurationTest {

    @Test
    void shouldAnyMatch(JenkinsRule jenkinsRule) {
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        assertTrue(config.anyMatch("**", ""), "** should match empty");
        assertTrue(config.anyMatch("/**", "/api"), "/** should match /api");
        assertTrue(config.anyMatch("/**", "/api/my-api"), "/** should match /api/my-api");
        assertTrue(config.anyMatch("/api/**", "/api"), "/api/** should match /api");
        assertTrue(config.anyMatch("/api/**", "/api/my-api"), "/api/** should match /api/my-api");
        assertFalse(config.anyMatch("/api/**", "/test/api"), "/api/** should NOT match /test/api");
        assertFalse(config.anyMatch("/api/**", "/test/api/my-api"), "/api/** should NOT match /test/api/my-api");
        assertTrue(config.anyMatch("/**/api/**", "/test/api"), "/**/api/** should match /test/api");
        assertTrue(config.anyMatch("/**/api/**", "/test/api/my-api"), "/**/api/** should match /test/api/my-api");
    }

    @Test
    void configRoundtrip(JenkinsRule jenkinsRule) throws Exception {

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        assertNotNull(config, "Configuration instance should not be null");
        String testJwksUrl = "https://keycloak.example.com/realms/test/protocol/openid-connect/certs";
        String testAudience = "test-jenkins";
        String testProtectedPaths = "**/api/**";

        // Set values and save
        config.setJwksUrl(testJwksUrl);
        config.setAllowedAudience(testAudience);
        config.setProtectedPaths(testProtectedPaths);
        config.save();

        // Round trip
        jenkinsRule.configRoundtrip();

        // Then - Verify values are set
        assertEquals(testJwksUrl, config.getJwksUrl(), "JWKS URL should match");
        assertEquals(testAudience, config.getAllowedAudience(), "Allowed audience should match");
        assertEquals(testProtectedPaths, config.getProtectedPaths(), "Protected paths should match");
    }
}
