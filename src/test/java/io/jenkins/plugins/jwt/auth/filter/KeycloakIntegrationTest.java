package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for JWT Bearer Token authentication using a real Keycloak instance via Testcontainers.
 */
@WithJenkins
class KeycloakIntegrationTest {

    private static final String REALM = "jenkins-test";
    private static final String CLIENT_ID = "jenkins";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_PASSWORD = "testpass";

    private static KeycloakContainer keycloak;

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer().withRealmImportFile("keycloak-test-realm.json");
        keycloak.start();
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    @Test
    void shouldReturn200WithValidJwtToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule);

        String token = getAccessToken();
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertEquals(200, statusCode, "Should return 200 with a valid JWT token");
    }

    @Test
    void shouldReturn401Or403WithoutToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule);

        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", null);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 when no JWT token is provided, got: " + statusCode);
    }

    @Test
    void shouldReturn401Or403WithInvalidToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule);

        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", "invalid.jwt.token");

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 with an invalid JWT token, got: " + statusCode);
    }

    /**
     * Configures Jenkins with the Keycloak JWKS URL as the JWT issuer and sets an authorization strategy
     * that requires authentication (logged-in users get full control, anonymous users get no access).
     */
    private void configureJenkins(JenkinsRule jenkinsRule) {
        String jwksUrl = keycloak.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/certs";
        Issuer issuer = new Issuer(jwksUrl, CLIENT_ID, "/**");
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer));

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        FullControlOnceLoggedInAuthorizationStrategy strategy = new FullControlOnceLoggedInAuthorizationStrategy();
        strategy.setAllowAnonymousRead(false);
        jenkinsRule.jenkins.setAuthorizationStrategy(strategy);
    }

    /**
     * Obtains an access token from Keycloak using the resource owner password credentials grant.
     */
    private String getAccessToken() throws Exception {
        String tokenUrl = keycloak.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/token";
        String requestBody = "grant_type=password&client_id=" + CLIENT_ID + "&username=" + TEST_USERNAME + "&password="
                + TEST_PASSWORD;

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "Keycloak token request should succeed");

        return extractJsonField(response.body(), "access_token");
    }

    /**
     * Sends a GET request to the given URL, optionally with a Bearer token.
     * Returns the HTTP response status code.
     */
    private int sendRequest(String url, String bearerToken) throws Exception {
        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest.Builder requestBuilder =
                HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (bearerToken != null) {
            requestBuilder.header("Authorization", "Bearer " + bearerToken);
        }
        return httpClient
                .send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
                .statusCode();
    }

    /**
     * Extracts a string field value from a JSON object using a simple regex.
     */
    private static String extractJsonField(String json, String fieldName) {
        Pattern pattern = Pattern.compile("\"" + fieldName + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        throw new IllegalStateException("Field '" + fieldName + "' not found in JSON response: " + json);
    }
}
