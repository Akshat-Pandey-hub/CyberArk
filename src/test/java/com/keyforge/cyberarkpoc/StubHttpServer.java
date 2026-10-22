package com.keyforge.cyberarkpoc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A loopback HTTP server that answers each path with a fixed status and body, for tests that need a
 * verbatim response body (e.g. an official example) rather than the mock CyberArk's own data.
 */
public final class StubHttpServer implements AutoCloseable {

    private record Reply(int status, String body) {
    }

    private final HttpServer server;
    private final Map<String, Reply> replies = new ConcurrentHashMap<>();
    private final List<String> authorizationHeaders = new CopyOnWriteArrayList<>();

    public StubHttpServer() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", this::handle);
        server.start();
    }

    /** Answers {@code path} (without query string) with this status and body. */
    public StubHttpServer reply(String path, int status, String body) {
        replies.put(path, new Reply(status, body));
        return this;
    }

    public String rootUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Authorization headers received on non-token paths, in order. */
    public List<String> authorizationHeaders() {
        return authorizationHeaders;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            exchange.getRequestBody().readAllBytes();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth != null) {
                authorizationHeaders.add(auth);
            }
            Reply reply = replies.getOrDefault(path, new Reply(404, "{}"));
            byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(reply.status(), bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        } finally {
            exchange.close();
        }
    }
}
