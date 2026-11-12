package com.keyforge.cyberarkpoc;

import com.keyforge.cyberarkpoc.check.PolicyHealthRun;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer.StandaloneRoute;
import com.keyforge.cyberarkpoc.store.DbConfig;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The CLI wrapper of the use cases: run statuses map to the documented exit codes. */
class MainCliTest {

    private static int exitFor(String status) {
        return Main.runStandalone("test", new StandaloneRoute("test", () -> Map.of("status", status)));
    }

    @Test
    void runStatusesMapToTheDocumentedExitCodes() {
        assertEquals(0, exitFor("SUCCESS"));
        assertEquals(6, exitFor("COMPLETED_WITH_FAILURES"));
        assertEquals(7, exitFor("INCOMPLETE"));
        assertEquals(2, exitFor("CONFIG_ERROR"));
        assertEquals(1, exitFor("FAILED"));
    }

    @Test
    void thePolicyHealthCommandFailsWithExitCode1WhenTheDatabaseIsUnreachable() {
        DbConfig noDb = new DbConfig("127.0.0.1", 1, "none", "u", "p", "cyberark");
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            int code = Main.runStandalone(Main.POLICY_HEALTH_ROUTE, new StandaloneRoute("use case 2",
                    () -> PolicyHealthRun.run(f.policyClient(Api.UAP), noDb)));

            assertEquals(1, code);
        }
    }

    @Test
    void thePolicyHealthRouteNeedsItsSettings() {
        // Uses the real environment: without CYBERARK_POLICY_* / CYBERARK_UAP_BASE_URL it is a configuration error.
        if (System.getenv(com.keyforge.cyberarkpoc.config.PolicyConfig.ENV_UAP_BASE_URL) == null) {
            assertEquals(2, Main.runStandalone(Main.POLICY_HEALTH_ROUTE, Main.policyHealthRoute()));
        }
    }
}
