package com.keyforge.cyberarkpoc.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CyberArkConfigTest {

    private static Map<String, String> validEnv() {
        Map<String, String> env = new HashMap<>();
        env.put(CyberArkConfig.ENV_IDENTITY_BASE_URL, "https://tenant.id.cyberark.cloud/");
        env.put(CyberArkConfig.ENV_UAP_BASE_URL, "https://sub.uap.cyberark.cloud/api");
        env.put(CyberArkConfig.ENV_CLIENT_ID, "svc-user");
        env.put(CyberArkConfig.ENV_CLIENT_SECRET, "s3cret-value");
        return env;
    }

    @Test
    void buildsFromEnvironmentWithDefaults() {
        CyberArkConfig config = CyberArkConfig.fromEnvironment(validEnv());

        assertEquals("https://tenant.id.cyberark.cloud", config.identityBaseUrl().toString());
        assertEquals("https://tenant.id.cyberark.cloud/oauth2/platformtoken", config.tokenUrl().toString());
        assertEquals("https://sub.uap.cyberark.cloud/api", config.uapBaseUrl().toString());
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
    void theUapUrlIsOnlyNeededForThePolicies() {
        Map<String, String> env = validEnv();
        env.remove(CyberArkConfig.ENV_UAP_BASE_URL);
        CyberArkConfig config = CyberArkConfig.fromEnvironment(env);

        assertNull(config.uapBaseUrl(), "use case 1 (Identity only) runs without it");
        ConfigException e = assertThrows(ConfigException.class,
                () -> new com.keyforge.cyberarkpoc.client.CyberArkClient(config).listPolicies());
        assertTrue(e.getMessage().contains(CyberArkConfig.ENV_UAP_BASE_URL));
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
        remote.put(CyberArkConfig.ENV_UAP_BASE_URL, "http://sub.uap.cyberark.cloud/api");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(remote));

        Map<String, String> local = validEnv();
        local.put(CyberArkConfig.ENV_UAP_BASE_URL, "http://127.0.0.1:8300/api");
        assertEquals("http://127.0.0.1:8300/api", CyberArkConfig.fromEnvironment(local).uapBaseUrl().toString());
    }

    @Test
    void badTimeoutIsRejected() {
        Map<String, String> env = validEnv();
        env.put(CyberArkConfig.ENV_TIMEOUT_SECONDS, "soon");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));

        env.put(CyberArkConfig.ENV_TIMEOUT_SECONDS, "0");
        assertThrows(ConfigException.class, () -> CyberArkConfig.fromEnvironment(env));
    }
}
