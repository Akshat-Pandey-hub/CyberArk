package com.keyforge.cyberarkpoc.client;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Stops a response body that is still arriving at the deadline: interrupts the reading thread and closes the stream.
 * Java's request timeout covers only the status and headers, so every body read (API responses and token responses)
 * runs under one of these.
 */
final class Deadline {

    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "cyberark-response-deadline");
        t.setDaemon(true);
        return t;
    });

    /** A body that did not arrive in full: the deadline passed ({@code late}) or the connection ended first. */
    static final class BodyIncomplete extends IOException {
        final boolean late;
        final int received;

        BodyIncomplete(boolean late, int received, IOException cause) {
            super(late ? "deadline passed" : "connection ended", cause);
            this.late = late;
            this.received = received;
        }
    }

    /**
     * Reads the whole stream within {@code nanos} and closes it. A body still arriving at the deadline, or one whose
     * connection ends early, throws {@link BodyIncomplete}; nothing of it is returned, so a partial body is never used.
     */
    static byte[] readAll(InputStream in, long nanos) throws BodyIncomplete {
        java.io.ByteArrayOutputStream received = new java.io.ByteArrayOutputStream();
        Deadline watch = new Deadline(Thread.currentThread(), in, Math.max(1, nanos));
        try (in) {
            in.transferTo(received);
            if (watch.stop()) { // the deadline fired just as the last byte arrived: treat as late
                throw new BodyIncomplete(true, received.size(), null);
            }
            return received.toByteArray();
        } catch (BodyIncomplete e) {
            throw e;
        } catch (IOException e) {
            throw new BodyIncomplete(watch.stop(), received.size(), e);
        } finally {
            watch.stop();
        }
    }

    private final Thread reader;
    private final InputStream in;
    private final ScheduledFuture<?> task;
    private int state; // 0 running, 1 done, 2 fired

    Deadline(Thread reader, InputStream in, long nanos) {
        this.reader = reader;
        this.in = in;
        this.task = DEADLINES.schedule(this::fire, nanos, TimeUnit.NANOSECONDS);
    }

    private void fire() {
        synchronized (this) {
            if (state != 0) {
                return;
            }
            state = 2;
            reader.interrupt();
        }
        try {
            in.close();
        } catch (IOException ignored) {
            // the interrupt already stops the read
        }
    }

    /** Ends the watch; returns whether the deadline fired (its interrupt is then cleared from this thread). */
    boolean stop() {
        synchronized (this) {
            if (state == 0) {
                state = 1;
            }
        }
        task.cancel(false);
        if (state == 2) {
            Thread.interrupted();
            return true;
        }
        return false;
    }
}
