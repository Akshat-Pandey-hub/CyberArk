package com.keyforge.cyberarkpoc;

import com.keyforge.cyberarkpoc.check.ApproverGroupCheck;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck;
import com.keyforge.cyberarkpoc.check.ReportPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer;
import com.keyforge.cyberarkpoc.store.DbConfig;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * {@code mock [port]} starts the local mock CyberArk (default port 8300).
 * {@code check} runs both use-case checks against the URLs in the CYBERARK_* environment variables
 * and prints a report. It only reads; it sends no notifications and writes nothing.
 * {@code pvwa-verify} logs on to PVWA, calls the documented Verify health check, prints it, and logs off.
 * {@code start-rest} starts the extraction REST service (see {@link ExtractionRestServer}).
 *
 * <p>Exit codes: 0 completed (checks may have findings), 1 a CyberArk call failed, 2 bad usage or
 * configuration.
 */
public final class Main {

    public static final int DEFAULT_MOCK_PORT = 8300;

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        switch (args[0]) {
            case "mock" -> runMock(args);
            case "check" -> System.exit(runCheck());
            case "pvwa-verify" -> System.exit(runPvwaRoute("pvwa/verify", true));
            case "pvwa-safes" -> System.exit(runPvwaRoute("pvwa/safes", false));
            case "pvwa-accounts" -> System.exit(runPvwaRoute("pvwa/accounts", false));
            case "pvwa-safe-members" -> System.exit(runPvwaRoute("pvwa/safe-members", false));
            case "pvwa-target-platforms" -> System.exit(runPvwaRoute("pvwa/target-platforms", false));
            case "pvwa-platform-details" -> System.exit(runPvwaRoute("pvwa/platform-details", false));
            case "pvwa-users" -> System.exit(runPvwaRoute("pvwa/users", false));
            case "pvwa-user-groups" -> System.exit(runPvwaRoute("pvwa/user-groups", false));
            case "pvwa-discovered-accounts" -> System.exit(runPvwaRoute("pvwa/discovered-accounts", false));
            case "start-rest" -> runRest();
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private static void runMock(String[] args) throws IOException, InterruptedException {
        int port = DEFAULT_MOCK_PORT;
        if (args.length > 1) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Port must be a number: " + args[1]);
                System.exit(2);
            }
        }
        MockCyberArkServer mock = MockCyberArkServer.start(SampleData.demo(), port);
        System.out.println("Mock CyberArk running at " + mock.rootUrl() + " (FABRICATED data, not a CyberArk tenant)");
        System.out.println(MockCyberArkServer.describeEndpoints(mock.rootUrl()));
        System.out.println("  Mock credentials: client_id=" + MockCyberArkServer.MOCK_CLIENT_ID
                + " client_secret=" + MockCyberArkServer.MOCK_CLIENT_SECRET);
        System.out.println("  Mock PVWA vault user: " + MockCyberArkServer.MOCK_VAULT_USERNAME + " / "
                + MockCyberArkServer.MOCK_VAULT_PASSWORD + " (PVWA base URL " + mock.rootUrl()
                + MockCyberArkServer.PVWA_APP + ")");
        System.out.println("Press Ctrl+C to stop.");
        CountDownLatch stop = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            mock.close();
            stop.countDown();
        }));
        stop.await();
    }

    private static int runCheck() {
        CyberArkConfig config;
        try {
            config = CyberArkConfig.fromEnvironment(System.getenv());
        } catch (ConfigException e) {
            System.err.println("Configuration error: " + e.getMessage());
            return 2;
        }
        System.out.println("Using " + config);
        CyberArkClient client = new CyberArkClient(config);
        try {
            ReportPrinter.print(new ApproverGroupCheck(client).run(), System.out);
            System.out.println();
            ReportPrinter.print(new PolicyHealthCheck(client).run(), System.out);
            System.out.println();
            System.out.println("Checks completed. No notifications were sent (out of scope for this phase).");
            return 0;
        } catch (CyberArkApiException e) {
            System.err.println("CHECK FAILED - a CyberArk call did not succeed: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Runs one route from the command line, exactly as {@code start-rest} would. Extraction routes print the run
     * summary without the records (they are in PostgreSQL). Exit codes follow Part 2: 0 SUCCESS,
     * 6 COMPLETED_WITH_FAILURES, 7 INCOMPLETE, 2 configuration, 1 failed.
     */
    private static int runPvwaRoute(String route, boolean printData) {
        PvwaConfig config;
        ExtractionSettings settings;
        try {
            config = PvwaConfig.fromEnvironment(System.getenv());
            settings = ExtractionSettings.fromEnvironment(System.getenv());
        } catch (ConfigException e) {
            System.err.println("Configuration error: " + e.getMessage());
            return 2;
        }
        System.out.println("Using " + config);
        Map<String, Object> result = ExtractionRestServer.run(route,
                ExtractionRestServer.pvwaRoutes(() -> DbConfig.fromEnvironment(System.getenv()), settings).get(route),
                () -> new PvwaClient(config));
        if (!printData) {
            result.remove("records");
        }
        try {
            System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result));
        } catch (IOException e) {
            System.out.println(result);
        }
        return switch (String.valueOf(result.get("status"))) {
            case "SUCCESS" -> 0;
            case "COMPLETED_WITH_FAILURES" -> 6;
            case "INCOMPLETE" -> 7;
            case "CONFIG_ERROR" -> 2;
            default -> 1;
        };
    }

    private static void runRest() throws IOException, InterruptedException {
        ExtractionRestServer.Settings settings;
        try {
            settings = ExtractionRestServer.Settings.fromEnvironment(System.getenv());
        } catch (ConfigException e) {
            System.err.println("Configuration error: " + e.getMessage());
            System.exit(2);
            return;
        }
        // The PVWA and database settings are read for every run, so a configuration error is reported in that
        // run's JSON instead of stopping the server.
        ExtractionSettings extraction;
        try {
            extraction = ExtractionSettings.fromEnvironment(System.getenv());
        } catch (ConfigException e) {
            System.err.println("Configuration error: " + e.getMessage());
            System.exit(2);
            return;
        }
        Map<String, ExtractionRestServer.Route> routes =
                ExtractionRestServer.pvwaRoutes(() -> DbConfig.fromEnvironment(System.getenv()), extraction);
        ExtractionRestServer rest = new ExtractionRestServer(settings,
                () -> new PvwaClient(PvwaConfig.fromEnvironment(System.getenv())), routes);
        rest.start();
        System.out.println("[rest] listening on http://" + settings.host() + ":" + rest.port()
                + ExtractionRestServer.BASE_PATH + "/<route>  (HTTP Basic Auth with REST_USERNAME / REST_PASSWORD; "
                + "one run at a time; Ctrl+C to stop)");
        routes.forEach((k, v) -> System.out.println("  GET "
                + ExtractionRestServer.BASE_PATH + "/" + k + "  - " + v.description()));
        CountDownLatch stop = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            rest.stop();
            stop.countDown();
        }));
        stop.await();
    }

    private static void usage() {
        System.err.println("Usage:");
        System.err.println("  java -jar cyberark-poc.jar mock [port]   start the local mock CyberArk (default "
                + DEFAULT_MOCK_PORT + ")");
        System.err.println("  java -jar cyberark-poc.jar check         run both checks (reads CYBERARK_* env vars)");
        System.err.println("  java -jar cyberark-poc.jar pvwa-verify   PVWA logon, Verify health check, logoff "
                + "(reads CYBERARK_PVWA_* env vars)");
        System.err.println("  java -jar cyberark-poc.jar pvwa-safes    extract all Safes into PostgreSQL "
                + "(CYBERARK_PVWA_* + PG_* env vars)");
        System.err.println("  java -jar cyberark-poc.jar pvwa-accounts extract all Accounts (secrets removed) "
                + "into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-safe-members extract the members of every Safe "
                + "into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-target-platforms extract all target platforms "
                + "into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-platform-details extract the details of every target "
                + "platform into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-users     extract all Vault users (needs Audit users) "
                + "into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-user-groups extract all user groups with members "
                + "(needs Audit users) into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar pvwa-discovered-accounts extract the pending discovered "
                + "accounts (needs Vault Admins or PVWAAccountsFeedAdmins) into PostgreSQL");
        System.err.println("  java -jar cyberark-poc.jar start-rest   start the extraction REST service "
                + "(REST_* + CYBERARK_PVWA_* + PG_* env vars)");
    }
}
