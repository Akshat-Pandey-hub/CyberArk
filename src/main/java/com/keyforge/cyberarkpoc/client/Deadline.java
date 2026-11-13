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
