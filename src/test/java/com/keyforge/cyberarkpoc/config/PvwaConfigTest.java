package com.keyforge.cyberarkpoc.config;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PvwaConfigTest {

    private static Map<String, String> env() {
        Map<String, String> env = new HashMap<>();
        env.put(PvwaConfig.ENV_BASE_URL, "https://pvwa.example.test/PasswordVault/");
        env.put(PvwaConfig.ENV_USERNAME, "svc-keyforge-readonly");
        env.put(PvwaConfig.ENV_PASSWORD, "p@ss word");
        return env;
    }

    @Test
    void defaultsToCyberArkAuthAndTrimsTheBaseUrl() {
        PvwaConfig config = PvwaConfig.fromEnvironment(env());

        assertEquals("https://pvwa.example.test/PasswordVault", config.baseUrl().toString());
        assertEquals("Cyberark", config.authMethod());
        assertEquals(PvwaConfig.DEFAULT_RENEW_AFTER, config.sessionRenewAfter());
    }

    @Test
    void authMethodIsOneOfTheDocumentedFour() {
        Map<String, String> env = env();
        for (String[] pair : new String[][] {{"ldap", "LDAP"}, {"RADIUS", "RADIUS"}, {"Windows", "Windows"},
                {"CyberArk", "Cyberark"}}) {
            env.put(PvwaConfig.ENV_AUTH_METHOD, pair[0]);
            assertEquals(pair[1], PvwaConfig.fromEnvironment(env).authMethod());
        }
        env.put(PvwaConfig.ENV_AUTH_METHOD, "SAML");
        assertThrows(ConfigException.class, () -> PvwaConfig.fromEnvironment(env));
    }

    @Test
    void requiredValuesAreChecked() {
        for (String key : new String[] {PvwaConfig.ENV_BASE_URL, PvwaConfig.ENV_USERNAME, PvwaConfig.ENV_PASSWORD}) {
            Map<String, String> env = env();
            env.remove(key);
            ConfigException e = assertThrows(ConfigException.class, () -> PvwaConfig.fromEnvironment(env));
            assertTrue(e.getMessage().contains(key), e.getMessage());
        }
    }

    @Test
    void httpsIsRequiredExceptForLocalhost() {
        Map<String, String> env = env();
        env.put(PvwaConfig.ENV_BASE_URL, "http://pvwa.example.test/PasswordVault");
        assertThrows(ConfigException.class, () -> PvwaConfig.fromEnvironment(env));

        env.put(PvwaConfig.ENV_BASE_URL, "http://127.0.0.1:8300/PasswordVault");
        assertEquals("http://127.0.0.1:8300/PasswordVault", PvwaConfig.fromEnvironment(env).baseUrl().toString());
    }

    @Test
    void toStringHidesThePassword() {
        assertFalse(PvwaConfig.fromEnvironment(env()).toString().contains("p@ss word"));
    }
}
