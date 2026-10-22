package com.keyforge.cyberarkpoc.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.ErrorSanitizer;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.extract.ExtractionRunner;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.extract.PvwaExtraction;
import com.keyforge.cyberarkpoc.store.DbConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * {@code start-rest}: the extraction service's HTTP interface, in the style of Part 2's REST wrapper.
 *
 * <p>{@code GET /cyberark-extract/<source>/<endpoint>} runs one extraction and answers with its JSON:
 * the run status plus the (redacted) CyberArk data. One run at a time (others get 409). Every request needs
 * HTTP Basic Auth with {@code REST_USERNAME} / {@code REST_PASSWORD}.
 *
 * <p>Each run opens its own CyberArk session and always closes it (PVWA logoff).
 */
public final class ExtractionRestServer {

    public static final String BASE_PATH = "/cyberark-extract";
    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final int DEFAULT_PORT = 8210;
    public static final String ENV_HOST = "REST_HOST";
    public static final String ENV_PORT = "REST_PORT";
    public static final String ENV_USERNAME = "REST_USERNAME";
    public static final String ENV_PASSWORD = "REST_PASSWORD";

    /**
     * One route: given an open PVWA client, produce the response fields (including {@code status}). The server
     * adds the envelope, the logon count and the logoff result.
     */
    public record Route(String description, Function<PvwaClient, Map<String, Object>> run) {
    }

    /**
     * The PVWA routes: the health check, and one extraction route per {@link PvwaExtraction} (fetch all pages,
     * store in PostgreSQL, return the run summary and the records). The database settings are read per run.
     */
    public static Map<String, Route> pvwaRoutes(Supplier<DbConfig> db, ExtractionSettings settings) {
        Map<String, Route> routes = new LinkedHashMap<>();
        routes.put("pvwa/verify", new Route(
                "Health check: GET /WebServices/PIMServices.svc/Verify/ (logon, call, logoff); stores nothing",
                client -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("status", "SUCCESS");
                    out.put("data", client.verify());
                    return out;
                }));
        for (PvwaExtraction extraction : PvwaExtraction.all(settings)) {
            routes.put(extraction.command().replaceFirst("^pvwa-", "pvwa/"), new Route(extraction.description(),
                    client -> ExtractionRunner.run(extraction, client, db.get())));
        }
        return routes;
    }

    /** HTTP status for a run status: like Part 2, a run that completed (even partially) answers 200. */
    static int httpStatus(Object status) {
        if (status == null) {
            return 500;
        }
        return switch (status.toString()) {
            case "SUCCESS", "COMPLETED_WITH_FAILURES", "INCOMPLETE" -> 200;
            case "CONFIG_ERROR" -> 500;
            default -> 502;
        };
    }

    public record Settings(String host, int port, String username, String password) {

        public Settings {
            if (port < 0 || port > 65535) {
                throw new ConfigException(ENV_PORT + " must be between 1 and 65535 but was: " + port);
            }
            if (username == null || username.isBlank() || password == null || password.isEmpty()) {
                throw new ConfigException("start-rest requires " + ENV_USERNAME + " and " + ENV_PASSWORD
                        + ": every request must authenticate with them (HTTP Basic Auth)");
            }
        }

        public static Settings fromEnvironment(Map<String, String> env) {
            String port = env.get(ENV_PORT);
            int p = DEFAULT_PORT;
            if (port != null && !port.isBlank()) {
                try {
                    p = Integer.parseInt(port.trim());
                } catch (NumberFormatException e) {
                    throw new ConfigException(ENV_PORT + " must be an integer but was: " + port);
                }
            }
            String host = env.get(ENV_HOST);
            return new Settings(host == null || host.isBlank() ? DEFAULT_HOST : host.trim(), p,
                    env.get(ENV_USERNAME), env.get(ENV_PASSWORD));
        }

        @Override
        public String toString() {
            return "Settings[host=" + host + ", port=" + port + ", username=" + username + ", password=***]";
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Settings settings;
    private final Supplier<PvwaClient> pvwa;
    private final Map<String, Route> routes;
    private final AtomicBoolean busy = new AtomicBoolean();
    private HttpServer server;
    private ExecutorService executor;

    /** {@code pvwa} creates a new client (and so a new session) per run; config errors surface per request. */
    public ExtractionRestServer(Settings settings, Supplier<PvwaClient> pvwa, Map<String, Route> routes) {
        this.settings = settings;
        this.pvwa = pvwa;
        this.routes = routes;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(settings.host(), settings.port()), 0);
        executor = Executors.newFixedThreadPool(4);
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private void handle(HttpExchange ex) {
        try {
            if (!authorized(ex.getRequestHeaders().getFirst("Authorization"))) {
                ex.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"cyberark-extract\", charset=\"UTF-8\"");
                send(ex, 401, error("missing or invalid credentials (HTTP Basic Auth)"));
                return;
            }
            if (!"GET".equals(ex.getRequestMethod())) {
                send(ex, 405, error("method not allowed: use GET"));
                return;
            }
            String path = ex.getRequestURI().getPath();
            if (path.equals(BASE_PATH) || path.equals(BASE_PATH + "/")) {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("usage", "GET " + BASE_PATH + "/<route>");
                Map<String, String> list = new LinkedHashMap<>();
                routes.forEach((k, v) -> list.put(k, v.description()));
                body.put("routes", list);
                send(ex, 200, body);
                return;
            }
            String name = path.startsWith(BASE_PATH + "/") ? path.substring(BASE_PATH.length() + 1) : "";
            Route route = routes.get(name);
            if (route == null) {
                send(ex, 404, error("unknown route " + path + "; see GET " + BASE_PATH + " for the routes"));
                return;
            }
            if (!busy.compareAndSet(false, true)) {
                send(ex, 409, error("another extraction is already running; nothing was started"));
                return;
            }
            Map<String, Object> result;
            try {
                result = execute(name, route);
            } finally {
                busy.set(false);
            }
            ex.getResponseHeaders().add("X-KF-Run-Status", String.valueOf(result.get("status")));
            send(ex, httpStatus(result.get("status")), result);
        } catch (IOException e) {
            System.err.println("[rest] could not send the response: " + ErrorSanitizer.clean(e.getMessage()));
        } catch (RuntimeException e) {
            // Last resort (e.g. a CyberArk client could not even be created): still answer with JSON.
            System.err.println("[rest] unexpected error: " + ErrorSanitizer.clean(e.getClass().getSimpleName()));
            try {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "FAILED");
                body.put("error_kind", "INTERNAL");
                body.put("error", "unexpected error: " + e.getClass().getSimpleName());
                send(ex, 500, body);
            } catch (IOException | RuntimeException ignored) {
                // the response was already started or the client went away; nothing more can be sent
            }
        } finally {
            ex.close();
        }
    }

    public Map<String, Object> execute(String name, Route route) {
        return run(name, route, pvwa);
    }

    /** Runs one route with its own session; the session is always logged off. Shared by the CLI. */
    public static Map<String, Object> run(String name, Route route, Supplier<PvwaClient> pvwa) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("route", name);
        body.put("started_at", Instant.now().toString());
        PvwaClient client;
        try {
            client = pvwa.get();
        } catch (ConfigException e) {
            body.put("status", "CONFIG_ERROR");
            body.put("error", e.getMessage());
            return body;
        }
        try (client) {
            body.putAll(route.run().apply(client));
        } catch (CyberArkApiException e) {
            body.put("status", "FAILED");
            body.put("error_kind", e.kind().name());
            body.put("http_status", e.httpStatus());
            body.put("error", client.sanitize(e.getMessage()));
        } catch (ConfigException e) {
            body.put("status", "CONFIG_ERROR");
            body.put("error", client.sanitize(e.getMessage()));
        } catch (RuntimeException e) {
            // Anything unexpected still gets a JSON answer; the session is closed by try-with-resources.
            body.put("status", "FAILED");
            body.put("error_kind", "INTERNAL");
            body.put("error", client.sanitize("unexpected error: " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage())));
        }
        body.put("logons", client.logonCount());
        body.put("logoff", client.logoffProblem() == null ? "ok" : client.logoffProblem());
        body.put("ended_at", Instant.now().toString());
        return body;
    }

    /** {@code Authorization: Basic base64(user:password)}, compared in constant time. */
    private boolean authorized(String header) {
        if (header == null || header.length() < 6 || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
            return false;
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            return false;
        }
        boolean user = MessageDigest.isEqual(decoded.substring(0, colon).getBytes(StandardCharsets.UTF_8),
                settings.username().getBytes(StandardCharsets.UTF_8));
        boolean pass = MessageDigest.isEqual(decoded.substring(colon + 1).getBytes(StandardCharsets.UTF_8),
                settings.password().getBytes(StandardCharsets.UTF_8));
        return user & pass;
    }

    private static Map<String, Object> error(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        return body;
    }

    private static void send(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
