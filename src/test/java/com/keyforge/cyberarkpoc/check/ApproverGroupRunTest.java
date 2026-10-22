package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer;
import com.keyforge.cyberarkpoc.store.DbConfig;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The use case 1 run and REST route without a database (database failures, configuration errors). */
class ApproverGroupRunTest {

    /** Nothing listens on this port, so connecting fails at once. */
    private static final DbConfig NO_DB = new DbConfig("127.0.0.1", 1, "none", "u", "p", "cyberark");

    @Test
    void anUnreachableDatabaseFailsBeforeAnyCyberArkCall() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> result = ApproverGroupRun.run(f.client, NO_DB, ApproverGroupRun.Settings.defaults());

            assertEquals("FAILED", result.get("status"));
            assertEquals("DATABASE", result.get("error_kind"));
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.TOKEN), "no login when nothing could be stored");
        }
    }

    @Test
    void aConfigurationErrorIsAJsonAnswerWithoutSecrets() {
        ExtractionRestServer.StandaloneRoute broken = new ExtractionRestServer.StandaloneRoute("test", () -> {
            throw new ConfigException("CYBERARK_CLIENT_SECRET is required");
        });

        Map<String, Object> result = ExtractionRestServer.run("ispss/approver-groups", broken);

        assertEquals("CONFIG_ERROR", result.get("status"));
        assertTrue(String.valueOf(result.get("error")).contains("CYBERARK_CLIENT_SECRET is required"));
        assertTrue(result.containsKey("ended_at"));
    }

    @Test
    void settingsComeFromTheEnvironmentWithDocumentedDefaults() {
        ApproverGroupRun.Settings defaults = ApproverGroupRun.Settings.fromEnvironment(Map.of());
        assertEquals(ApproverGroupCheck.DEFAULT_PATTERN, defaults.rolePattern());
        assertEquals(3, defaults.minApprovers());

        ApproverGroupRun.Settings custom = ApproverGroupRun.Settings.fromEnvironment(Map.of(
                "CYBERARK_APPROVER_ROLE_PATTERN", "APP-%-X", "CYBERARK_MIN_APPROVERS", "4",
                "CYBERARK_REDROCK_PAGE_SIZE", "50"));
        assertEquals("APP-%-X", custom.rolePattern());
        assertEquals(4, custom.minApprovers());
        assertEquals(50, custom.pageSize());
        assertFalse(org.junit.jupiter.api.Assertions.assertThrows(ConfigException.class,
                () -> ApproverGroupRun.Settings.fromEnvironment(Map.of("CYBERARK_MIN_APPROVERS", "x")))
                .getMessage().isBlank());
    }
}
