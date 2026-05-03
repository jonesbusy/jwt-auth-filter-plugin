package io.jenkins.plugins.jwt.auth.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
 * Two realms are imported into a single Keycloak container to cover multi-issuer scenarios.
 */
@WithJenkins
class KeycloakIntegrationTest {

    private static final String REALM_1 = "jenkins-test";
    private static final String CLIENT_ID_1 = "jenkins";
    // Client in realm1 without an audience protocol mapper (used to produce tokens without aud=jenkins)
    private static final String CLIENT_NO_AUD_ID = "jenkins-no-aud";

    private static final String REALM_2 = "jenkins-test-2";
    private static final String CLIENT_ID_2 = "jenkins2";

    // Intentionally simple credentials used only within the isolated test container
    private static final String TEST_USERNAME_1 = "testuser";
    private static final String TEST_PASSWORD_1 = "testpass";
    private static final String TEST_USERNAME_2 = "testuser2";
    private static final String TEST_PASSWORD_2 = "testpass2";

    private static KeycloakContainer keycloak;

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer()
                .withRealmImportFile("keycloak-test-realm.json")
                .withRealmImportFile("keycloak-test-realm2.json");
        keycloak.start();
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    // ---- Basic JWT validation tests ----

    @Test
    void shouldReturn200WithValidJwtToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule, REALM_1, CLIENT_ID_1, "/**");

        String token = getAccessToken(REALM_1, CLIENT_ID_1, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertEquals(200, statusCode, "Should return 200 with a valid JWT token");
    }

    @Test
    void shouldReturn401Or403WithoutToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule, REALM_1, CLIENT_ID_1, "/**");

        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", null);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 when no JWT token is provided, got: " + statusCode);
    }

    @Test
    void shouldReturn401Or403WithInvalidToken(JenkinsRule jenkinsRule) throws Exception {
        configureJenkins(jenkinsRule, REALM_1, CLIENT_ID_1, "/**");

        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", "invalid.jwt.token");

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 with an invalid JWT token, got: " + statusCode);
    }

    // ---- Audience validation tests ----

    @Test
    void shouldReturn401Or403WithWrongAudience(JenkinsRule jenkinsRule) throws Exception {
        // Issuer expects "wrong-audience" but the token will carry aud=["jenkins"]
        configureJenkins(jenkinsRule, REALM_1, "wrong-audience", "/**");

        String token = getAccessToken(REALM_1, CLIENT_ID_1, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 when token audience doesn't match issuer, got: " + statusCode);
    }

    @Test
    void shouldReturn401Or403WithMissingAudience(JenkinsRule jenkinsRule) throws Exception {
        // Issuer expects "jenkins" but the token from jenkins-no-aud client won't include that audience
        configureJenkins(jenkinsRule, REALM_1, CLIENT_ID_1, "/**");

        String token = getAccessToken(REALM_1, CLIENT_NO_AUD_ID, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 when token has no matching audience, got: " + statusCode);
    }

    // ---- Username claim mapping test ----

    @Test
    void shouldReturn401Or403WithMissingUsernameClaim(JenkinsRule jenkinsRule) throws Exception {
        // Configure issuer with a username claim that is absent from the token
        String jwksUrl = keycloak.getAuthServerUrl() + "/realms/" + REALM_1 + "/protocol/openid-connect/certs";
        Issuer issuer = new Issuer(jwksUrl, CLIENT_ID_1, "/**");
        issuer.setUsernameClaim("nonexistent_claim");
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer));
        enableSecurityRealm(jenkinsRule);

        String token = getAccessToken(REALM_1, CLIENT_ID_1, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Should return 401 or 403 when username claim is missing from token, got: " + statusCode);
    }

    // ---- Two-issuer tests with different protected paths ----

    @Test
    void shouldReturn200WithFirstIssuerOnItsProtectedPath(JenkinsRule jenkinsRule) throws Exception {
        configureTwoIssuers(jenkinsRule);

        // Realm1 token on issuer1's path -> issuer1 validates it
        String token = getAccessToken(REALM_1, CLIENT_ID_1, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "api/json", token);

        assertEquals(200, statusCode, "Realm1 token should return 200 on issuer1's protected path");
    }

    @Test
    void shouldReturn200WithSecondIssuerOnItsProtectedPath(JenkinsRule jenkinsRule) throws Exception {
        configureTwoIssuers(jenkinsRule);

        // Realm2 token on issuer2's path -> issuer2 validates it
        String token = getAccessToken(REALM_2, CLIENT_ID_2, TEST_USERNAME_2, TEST_PASSWORD_2);
        int statusCode = sendRequest(jenkinsRule.getURL() + "view/all/api/json", token);

        assertEquals(200, statusCode, "Realm2 token should return 200 on issuer2's protected path");
    }

    @Test
    void shouldReturn401Or403WithFirstIssuerTokenOnSecondIssuerPath(JenkinsRule jenkinsRule) throws Exception {
        configureTwoIssuers(jenkinsRule);

        // Realm1 token on issuer2's path: issuer1 doesn't protect that path,
        // issuer2 does but cannot validate realm1's token (wrong audience + wrong JWKS)
        String token = getAccessToken(REALM_1, CLIENT_ID_1, TEST_USERNAME_1, TEST_PASSWORD_1);
        int statusCode = sendRequest(jenkinsRule.getURL() + "view/all/api/json", token);

        assertTrue(
                statusCode == 401 || statusCode == 403,
                "Realm1 token should be rejected on issuer2's path, got: " + statusCode);
    }

    // ---- Helper methods ----

    /**
     * Configures Jenkins with a single issuer whose JWKS comes from the given Keycloak realm.
     */
    private void configureJenkins(
            JenkinsRule jenkinsRule, String realm, String allowedAudience, String protectedPaths) {
        String jwksUrl = keycloak.getAuthServerUrl() + "/realms/" + realm + "/protocol/openid-connect/certs";
        Issuer issuer = new Issuer(jwksUrl, allowedAudience, protectedPaths);
        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer));
        enableSecurityRealm(jenkinsRule);
    }

    /**
     * Configures Jenkins with two issuers protecting different path prefixes:
     * issuer1 (realm1) protects /api/**, issuer2 (realm2) protects /view/**.
     */
    private void configureTwoIssuers(JenkinsRule jenkinsRule) throws Exception {
        // Derive the context path (e.g. "/jenkins") to build per-issuer path patterns
        String basePath = jenkinsRule.getURL().getPath().replaceAll("/$", "");

        String jwksUrl1 = keycloak.getAuthServerUrl() + "/realms/" + REALM_1 + "/protocol/openid-connect/certs";
        Issuer issuer1 = new Issuer(jwksUrl1, CLIENT_ID_1, basePath + "/api/**");

        String jwksUrl2 = keycloak.getAuthServerUrl() + "/realms/" + REALM_2 + "/protocol/openid-connect/certs";
        Issuer issuer2 = new Issuer(jwksUrl2, CLIENT_ID_2, basePath + "/view/**");

        JwtBearerTokenFilterConfiguration config = JwtBearerTokenFilterConfiguration.getInstance();
        config.setIssuers(List.of(issuer1, issuer2));
        enableSecurityRealm(jenkinsRule);
    }

    /**
     * Locks down Jenkins: authenticated users get full control, anonymous users have no access.
     */
    private void enableSecurityRealm(JenkinsRule jenkinsRule) {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        FullControlOnceLoggedInAuthorizationStrategy strategy = new FullControlOnceLoggedInAuthorizationStrategy();
        strategy.setAllowAnonymousRead(false);
        jenkinsRule.jenkins.setAuthorizationStrategy(strategy);
    }

    /**
     * Obtains a JWT access token from Keycloak via the resource owner password credentials grant.
     */
    private String getAccessToken(String realm, String clientId, String username, String password) throws Exception {
        String tokenUrl = keycloak.getAuthServerUrl() + "/realms/" + realm + "/protocol/openid-connect/token";
        String requestBody = "grant_type=password"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);

        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(
                200,
                response.statusCode(),
                "Keycloak token request should succeed for realm=" + realm + " client=" + clientId);
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
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        throw new IllegalStateException("Field '" + fieldName + "' not found in JSON response: " + json);
    }
}
