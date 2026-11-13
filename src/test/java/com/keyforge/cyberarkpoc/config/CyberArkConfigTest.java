package com.keyforge.cyberarkpoc.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CyberArkConfigTest {

    private static Map<String, String> validEnv() {
        Map<String, String> env = new HashMap<>();
        env.put(CyberArkConfig.ENV_IDENTITY_BASE_URL, "https://tenant.id.cyberark.cloud/");
        env.put(CyberArkConfig.ENV_CLIENT_ID, "svc-user");
        env.put(CyberArkConfig.ENV_CLIENT_SECRET, "s3cret-value");
        return env;
    }

    @Test
    void buildsFromEnvironmentWithDefaults() {
        CyberArkConfig config = CyberArkConfig.fromEnvironment(validEnv());

        assertEquals("https://tenant.id.cyberark.cloud", config.identityBaseUrl().toString());
        assertEquals("https://tenant.id.cyberark.cloud/oauth2/platformtoken", config.tokenUrl().toString());
        assertEquals(CyberArkConfig.DEFAULT_TIMEOUT, config.requestTimeout());
    }

    @Test
    void tokenUrlAndTimeoutCanBeOverridden() {
        Map<String, String> env = validEnv();
        env.put(CyberArkConfig.ENV_TOKEN_URL, "https://other.id.cyberark.cloud/oauth2/platformtoken");
        env.put(CyberArkConfig.ENV_TIMEOUT_SECONDS, "10");

        CyberArkConfig config = CyberArkConfig.fromEnvironment(env);

        assertEquals("https://other.id.cyberark.cloud/oauth2/platformtoken", config.tokenUrl().toString());
        assertEquals(Duration.ofSeconds(10), config.requestTimeout());
    }

    @Test
    void toStringHidesTheSecret() {
        String text = CyberArkConfig.fromEnvironment(validEnv()).toString();

        assertFalse(text.contains("s3cret-value"));
        assertTrue(text.contains("clientSecret=***"));
    }

    @Test
    void missingValuesAreRejected() {
        for (String key : new String[] {CyberArkConfig.ENV_IDENTITY_BASE_URL,
                CyberArkConfig.ENV_CLIENT_ID, CyberArkConfig.ENV_CLIENT_SECRET}) {
            Map<String, String> env = validEnv();
            env.remove(key);
            ConfigException e = assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));
            assertTrue(e.getMessage().contains(key), e.getMessage());
        }
    }

    @Test
    void theRoleMembersApiIsSelectable() {
        assertEquals(CyberArkConfig.RoleMembersApi.ROLES, CyberArkConfig.roleMembersApi(Map.of()));
        assertEquals(CyberArkConfig.RoleMembersApi.SAASMANAGE,
                CyberArkConfig.roleMembersApi(Map.of(CyberArkConfig.ENV_ROLE_MEMBERS_API, "SaasManage")));
        assertThrows(ConfigException.class,
                () -> CyberArkConfig.roleMembersApi(Map.of(CyberArkConfig.ENV_ROLE_MEMBERS_API, "other")));
    }

    @Test
    void plainHttpIsOnlyAllowedForLocalhost() {
        Map<String, String> remote = validEnv();
        remote.put(CyberArkConfig.ENV_IDENTITY_BASE_URL, "http://tenant.id.cyberark.cloud");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(remote));

        Map<String, String> local = validEnv();
        local.put(CyberArkConfig.ENV_IDENTITY_BASE_URL, "http://127.0.0.1:8300/api");
        assertEquals("http://127.0.0.1:8300/api", CyberArkConfig.fromEnvironment(local).identityBaseUrl().toString());
    }

    @Test
    void badTimeoutIsRejected() {
        Map<String, String> env = validEnv();
        env.put(CyberArkConfig.ENV_TIMEOUT_SECONDS, "soon");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));

        env.put(CyberArkConfig.ENV_TIMEOUT_SECONDS, "0");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));
    }

    @Test
    void identityLoginDefaultsToThePlatformTokenAndRedrockGetsTheLongerTimeout() {
        CyberArkConfig config = CyberArkConfig.fromEnvironment(validEnv());

        assertEquals(CyberArkConfig.AuthMethod.PLATFORM, config.authMethod());
        assertEquals(CyberArkConfig.DEFAULT_REDROCK_TIMEOUT, config.redrockTimeout());
        assertEquals(Duration.ofSeconds(130), config.redrockTimeout());
    }

    @Test
    void theOauth2AppLoginBuildsItsTokenUrlFromTheAppId() {
        Map<String, String> env = validEnv();
        env.put(CyberArkConfig.ENV_IDENTITY_AUTH, "oauth2-app");
        env.put(CyberArkConfig.ENV_IDENTITY_APP_ID, "identityapi");
        env.put(CyberArkConfig.ENV_IDENTITY_SCOPE, "reporting");
        env.put(CyberArkConfig.ENV_IDENTITY_TOKEN_BODY, "JSON");
        env.put(CyberArkConfig.ENV_REDROCK_TIMEOUT_SECONDS, "200");

        CyberArkConfig config = CyberArkConfig.fromEnvironment(env);

        assertEquals(CyberArkConfig.AuthMethod.OAUTH2_APP, config.authMethod());
        assertEquals("https://tenant.id.cyberark.cloud/oauth2/token/identityapi", config.tokenUrl().toString());
        assertEquals("reporting", config.tokenScope());
        assertEquals(CyberArkConfig.TokenBody.JSON, config.tokenBody());
        assertEquals(Duration.ofSeconds(200), config.redrockTimeout());
    }

    @Test
    void theOauth2AppLoginNeedsAnAppIdOrTokenUrlAndValidValues() {
        Map<String, String> env = validEnv();
        env.put(CyberArkConfig.ENV_IDENTITY_AUTH, "oauth2-app");
        ConfigException e = assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));
        assertTrue(e.getMessage().contains(CyberArkConfig.ENV_IDENTITY_APP_ID), e.getMessage());

        env.put(CyberArkConfig.ENV_TOKEN_URL, "https://tenant.id.cyberark.cloud/oauth2/token/x");
        assertEquals("https://tenant.id.cyberark.cloud/oauth2/token/x",
                CyberArkConfig.fromEnvironment(env).tokenUrl().toString());

        Map<String, String> bad = validEnv();
        bad.put(CyberArkConfig.ENV_IDENTITY_AUTH, "other");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(bad));
        Map<String, String> badBody = validEnv();
        badBody.put(CyberArkConfig.ENV_IDENTITY_TOKEN_BODY, "xml");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(badBody));
    }
}
