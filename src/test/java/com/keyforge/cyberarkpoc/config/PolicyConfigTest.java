package com.keyforge.cyberarkpoc.config;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyConfigTest {

    private static Map<String, String> validEnv() {
        Map<String, String> env = new HashMap<>();
        env.put(CyberArkConfig.ENV_IDENTITY_BASE_URL, "https://tenant.id.cyberark.cloud/");
        env.put(PolicyConfig.ENV_POLICY_APP_ID, "kfpolicies");
        env.put(PolicyConfig.ENV_UAP_BASE_URL, "https://sub.uap.cyberark.cloud/api");
        env.put(PolicyConfig.ENV_POLICY_CLIENT_ID, "svc-policies");
        env.put(PolicyConfig.ENV_POLICY_CLIENT_SECRET, "p0licy-secret");
        return env;
    }

    @Test
    void defaultsToUapWithTheCustomTokenUrlFromTheAppId() {
        PolicyConfig config = PolicyConfig.fromEnvironment(validEnv());

        assertEquals(PolicyConfig.Api.UAP, config.api());
        assertEquals("https://sub.uap.cyberark.cloud/api", config.baseUrl().toString());
        assertEquals("https://tenant.id.cyberark.cloud/oauth2/token/kfpolicies", config.tokenUrl().toString());
        assertEquals(50, config.pageSize());
        assertEquals("svc-policies", config.clientId());
    }

    @Test
    void anExplicitTokenUrlWinsAndTheAppIdIsThenNotNeeded() {
        Map<String, String> env = validEnv();
        env.remove(PolicyConfig.ENV_POLICY_APP_ID);
        env.put(PolicyConfig.ENV_POLICY_TOKEN_URL, "https://other.id.cyberark.cloud/oauth2/token/x");

        assertEquals("https://other.id.cyberark.cloud/oauth2/token/x",
                PolicyConfig.fromEnvironment(env).tokenUrl().toString());
    }

    @Test
    void withoutTokenUrlOrAppIdTheConfigurationIsRejected() {
        Map<String, String> env = validEnv();
        env.remove(PolicyConfig.ENV_POLICY_APP_ID);
        ConfigException e = assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
        assertTrue(e.getMessage().contains(PolicyConfig.ENV_POLICY_APP_ID), e.getMessage());

        Map<String, String> bad = validEnv();
        bad.put(PolicyConfig.ENV_POLICY_APP_ID, "a/b");
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(bad));
    }

    @Test
    void scaNeedsTheScaBaseUrl() {
        Map<String, String> env = validEnv();
        env.put(PolicyConfig.ENV_POLICY_API, "SCA");
        ConfigException e = assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
        assertTrue(e.getMessage().contains(PolicyConfig.ENV_SCA_BASE_URL), e.getMessage());

        env.put(PolicyConfig.ENV_SCA_BASE_URL, "https://sub.sca.cyberark.cloud/api/");
        PolicyConfig config = PolicyConfig.fromEnvironment(env);
        assertEquals(PolicyConfig.Api.SCA, config.api());
        assertEquals("https://sub.sca.cyberark.cloud/api", config.baseUrl().toString());

        env.put(PolicyConfig.ENV_POLICY_API, "other");
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
    }

    @Test
    void credentialsFallBackToTheIdentityServiceUser() {
        Map<String, String> env = validEnv();
        env.remove(PolicyConfig.ENV_POLICY_CLIENT_ID);
        env.remove(PolicyConfig.ENV_POLICY_CLIENT_SECRET);
        env.put(CyberArkConfig.ENV_CLIENT_ID, "svc-identity");
        env.put(CyberArkConfig.ENV_CLIENT_SECRET, "identity-secret");

        PolicyConfig config = PolicyConfig.fromEnvironment(env);
        assertEquals("svc-identity", config.clientId());
        assertEquals("identity-secret", config.clientSecret());

        env.remove(CyberArkConfig.ENV_CLIENT_SECRET);
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
    }

    @Test
    void pageSizeMustStayWithinTheDocumentedMaximum() {
        Map<String, String> env = validEnv();
        env.put(PolicyConfig.ENV_POLICY_PAGE_SIZE, "10");
        assertEquals(10, PolicyConfig.fromEnvironment(env).pageSize());
        env.put(PolicyConfig.ENV_POLICY_PAGE_SIZE, "51");
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
        env.put(PolicyConfig.ENV_POLICY_PAGE_SIZE, "x");
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));
    }

    @Test
    void plainHttpIsOnlyAllowedForLocalhostAndTheSecretIsNeverPrinted() {
        Map<String, String> env = validEnv();
        env.put(PolicyConfig.ENV_UAP_BASE_URL, "http://sub.uap.cyberark.cloud/api");
        assertThrows(ConfigException.class, () -> PolicyConfig.fromEnvironment(env));

        String text = PolicyConfig.fromEnvironment(validEnv()).toString();
        assertFalse(text.contains("p0licy-secret"));
        assertTrue(text.contains("clientSecret=***"));
    }

    @Test
    void theTokenBodyDefaultsToJsonAndScopeAndFormCanBeSet() {
        PolicyConfig defaults = PolicyConfig.fromEnvironment(validEnv());
        assertEquals(CyberArkConfig.TokenBody.JSON, defaults.tokenBody());
        assertEquals(null, defaults.tokenScope());

        Map<String, String> env = validEnv();
        env.put(PolicyConfig.ENV_POLICY_TOKEN_BODY, "form");
        env.put(PolicyConfig.ENV_POLICY_SCOPE, "sca");
        PolicyConfig config = PolicyConfig.fromEnvironment(env);
        assertEquals(CyberArkConfig.TokenBody.FORM, config.tokenBody());
        assertEquals("sca", config.tokenScope());
    }
}
