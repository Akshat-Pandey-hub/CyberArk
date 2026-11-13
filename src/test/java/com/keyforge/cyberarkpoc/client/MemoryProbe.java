package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;

import java.io.BufferedOutputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Run in a separate JVM with a small heap (see {@code LargeResponseTest}): several large Redrock answers are received,
 * checked and written out as the REST envelope at the same time. With the whole body in memory this would need many
 * times the heap; streamed, it fits. Prints one {@code RESULT} line.
 */
public final class MemoryProbe {

    public static void main(String[] args) throws Exception {
        int rows = Integer.parseInt(args[0]);
        int threads = Integer.parseInt(args[1]);
        Path spoolDir = Path.of(args[2]);
        ResponseBody.Settings spool = new ResponseBody.Settings(spoolDir, ResponseBody.MEMORY_BYTES, 0, 0,
                Duration.ofHours(24));
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        AtomicLong peak = new AtomicLong();
        Thread sampler = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                peak.accumulateAndGet(memory.getHeapMemoryUsage().getUsed(), Math::max);
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    return;
                }
            }
        });
        sampler.setDaemon(true);
        sampler.start();
        ObjectMapper mapper = new ObjectMapper();
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/api/oauth2/platformtoken", 200, "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}")
                .handle("/api/Redrock/query", ex -> {
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(200, 0);
                    try (OutputStream o = new BufferedOutputStream(ex.getResponseBody(), 64 * 1024)) {
                        LargeBodies.redrock(o, rows);
                    }
                })) {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            List<Future<String>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    CloudApi api = new CloudApi(new CyberArkConfig(URI.create(stub.rootUrl() + "/api"), null,
                            "client", "secret-value", Duration.ofSeconds(120)), null).withSpool(spool);
                    Map<String, Object> out = api.redrock("SELECT ID, Name FROM Role", 1, rows + 1, null, -1);
                    try {
                        LargeBodies.Digest written = new LargeBodies.Digest();
                        mapper.writerWithDefaultPrettyPrinter().writeValue(written, out); // the REST writer path
                        Object records = ((Map<?, ?>) out.get("completeness")).get("records_in_response");
                        return out.get("ok") + "/" + records + "/" + out.get("response_bytes") + "/" + written.size();
                    } finally {
                        ResponseBody.release(out);
                    }
                }));
            }
            int ok = 0;
            long bodyBytes = 0;
            for (Future<String> f : results) {
                String[] r = f.get().split("/");
                if (r[0].equals("true") && r[1].equals(String.valueOf(rows))) {
                    ok++;
                    bodyBytes += Long.parseLong(r[2]);
                }
            }
            pool.shutdown();
            sampler.interrupt();
            long left;
            try (var files = Files.list(spoolDir)) {
                left = files.count();
            }
            System.out.println("RESULT ok=" + ok + " threads=" + threads + " totalBodyMB=" + bodyBytes / 1048576
                    + " maxHeapMB=" + Runtime.getRuntime().maxMemory() / 1048576 + " peakHeapUsedMB="
                    + peak.get() / 1048576 + " filesLeft=" + left);
            System.exit(ok == threads && left == 0 ? 0 : 1);
        }
    }
}
