package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer;
import com.keyforge.cyberarkpoc.store.DbConfig;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The use case 2 run and its REST/CLI wrapper without a database (database failures, configuration errors). */
class PolicyHealthRunTest {

    /** Nothing listens on this port, so connecting fails at once. */
    private static final DbConfig NO_DB = new DbConfig("127.0.0.1", 1, "none", "u", "p", "cyberark");

    @Test
    void anUnreachableDatabaseFailsBeforeAnyCyberArkCallAndConcludesNothing() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.UAP), NO_DB);

            assertEquals("FAILED", result.get("status"));
            assertEquals("DATABASE", result.get("error_kind"));
            assertEquals("UNDETERMINED", result.get("health"));
            assertEquals(PolicyHealthRun.FAILED_NOTE, result.get("health_note"));
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICY_TOKEN), "no login when nothing could be stored");
        }
    }

    @Test
    void aConfigurationErrorIsAJsonAnswer() {
        ExtractionRestServer.StandaloneRoute broken = new ExtractionRestServer.StandaloneRoute("test", () -> {
            throw new ConfigException("CYBERARK_POLICY_APP_ID is required");
        });

        Map<String, Object> result = ExtractionRestServer.run("ispss/policy-health", broken);

        assertEquals("CONFIG_ERROR", result.get("status"));
        assertTrue(String.valueOf(result.get("error")).contains("CYBERARK_POLICY_APP_ID"));
    }
}
