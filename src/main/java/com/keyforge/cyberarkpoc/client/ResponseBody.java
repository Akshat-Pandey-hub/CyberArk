package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.keyforge.cyberarkpoc.config.ConfigException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CyberArk's response body exactly as received (its bytes, unchanged). A small body is kept in memory; a larger one is
 * written to a temporary file as it arrives, so memory use does not grow with the size of the response. When the
 * envelope is written as JSON, the body is copied into it from there in small pieces.
 *
 * <p>Temporary files: created owner-only in {@link Settings#dir()}, deleted by {@link #close()} (which every caller
 * runs when the response has been sent), on any failure while receiving, by a cleaner if an instance is ever dropped
 * without being closed, at JVM shutdown, and (for files left by a crash) by a sweep of files older than
 * {@link Settings#abandonedAfter()} the first time a directory is used. Free disk space is checked while writing: the
 * response is refused with an explicit error (never cut short) before the free space falls below
 * {@link Settings#minFreeBytes()}. {@link Settings#maxBytes()} is an optional local limit, off by default.
 */
@JsonSerialize(using = ResponseBody.Serializer.class)
public final class ResponseBody implements AutoCloseable {

    public static final String FILE_PREFIX = "cyberark-response-";
    public static final String FILE_SUFFIX = ".tmp";

    public static final String ENV_DIR = "CYBERARK_SPOOL_DIR";
    public static final String ENV_MIN_FREE_MB = "CYBERARK_SPOOL_MIN_FREE_MB";
    public static final String ENV_MAX_RESPONSE_MB = "CYBERARK_MAX_RESPONSE_MB";

    /** Bodies up to this size stay in memory; an internal choice, not a limit on the response. */
    static final int MEMORY_BYTES = 1024 * 1024;
    static final long DEFAULT_MIN_FREE_BYTES = 512L * 1024 * 1024;
    static final Duration ABANDONED_AFTER = Duration.ofHours(24);
    private static final long FREE_SPACE_CHECK_EVERY = 8L * 1024 * 1024;

    private static final Cleaner CLEANER = Cleaner.create();
    private static final Set<Path> OPEN_FILES = ConcurrentHashMap.newKeySet();
    private static final Set<Path> SWEPT_DIRS = ConcurrentHashMap.newKeySet();

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> OPEN_FILES.forEach(ResponseBody::deleteQuietly),
                "cyberark-response-cleanup"));
    }

    /**
     * Where and how bodies are kept.
     *
     * @param dir            directory for temporary files (created owner-only if absent)
     * @param memoryBytes    bodies up to this size stay in memory
     * @param maxBytes       optional local limit on one response; 0 = none (default). Not a CyberArk limit
     * @param minFreeBytes   a response is refused before the free space of {@code dir} falls below this
     * @param abandonedAfter temporary files older than this are taken as left by a crash and deleted
     */
    public record Settings(Path dir, int memoryBytes, long maxBytes, long minFreeBytes, Duration abandonedAfter) {

        public static Settings defaults() {
            return new Settings(Path.of(System.getProperty("java.io.tmpdir"), "cyberark-poc-responses"),
                    MEMORY_BYTES, 0, DEFAULT_MIN_FREE_BYTES, ABANDONED_AFTER);
        }

        /** {@value #ENV_DIR}, {@value #ENV_MIN_FREE_MB} (default 512) and {@value #ENV_MAX_RESPONSE_MB} (default none). */
        public static Settings fromEnvironment(Map<String, String> env) {
            Settings d = defaults();
            String dir = env.get(ENV_DIR);
            return new Settings(dir == null || dir.isBlank() ? d.dir() : Path.of(dir.trim()), d.memoryBytes(),
                    megabytes(env, ENV_MAX_RESPONSE_MB, 0), megabytes(env, ENV_MIN_FREE_MB, d.minFreeBytes()),
                    d.abandonedAfter());
        }

        private static long megabytes(Map<String, String> env, String name, long fallback) {
            String value = env.get(name);
            if (value == null || value.isBlank()) {
                return fallback;
            }
            try {
                long mb = Long.parseLong(value.trim());
                if (mb < 0) {
                    throw new NumberFormatException();
                }
                return mb * 1024 * 1024;
            } catch (NumberFormatException e) {
                throw new ConfigException(name + " must be a whole number of megabytes (0 or more) but was: " + value);
            }
        }
    }

    /** A local protection (disk reserve or the optional maximum) stopped the download; never a CyberArk limit. */
    public static final class LocalLimitException extends IOException {
        LocalLimitException(String message) {
            super(message);
        }
    }

    private final byte[] memory;
    private final Path file;
    private final long size;
    private final Cleaner.Cleanable cleanable;
    private volatile boolean text;

    private ResponseBody(byte[] memory, Path file, long size) {
        this.memory = memory;
        this.file = file;
        this.size = size;
        this.cleanable = file == null ? null : CLEANER.register(this, () -> deleteQuietly(file));
    }

    public long size() {
        return size;
    }

    /** Whether the body is in a temporary file (as opposed to memory). */
    public boolean spooled() {
        return file != null;
    }

    public InputStream open() throws IOException {
        return memory != null ? new ByteArrayInputStream(memory) : Files.newInputStream(file);
    }

    /** The body parsed as a tree (exact numbers), for in-process callers and tests; builds it in memory. */
    public JsonNode tree() {
        try (InputStream in = open()) {
            return CloudApi.EXACT.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException("could not read the response: " + e.getMessage(), e);
        }
    }

    /** The body as text; builds it in memory. */
    public String text() {
        try (InputStream in = open()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("could not read the response: " + e.getMessage(), e);
        }
    }

    /** From now on the body is written into JSON as a string (for {@code response_text}) instead of as JSON. */
    ResponseBody asText() {
        this.text = true;
        return this;
    }

    @Override
    public void close() {
        if (cleanable != null) {
            cleanable.clean();
        }
    }

    @Override
    public String toString() {
        return "ResponseBody[" + size + " bytes" + (file != null ? ", spooled" : "") + "]";
    }

    /** Closes every {@link ResponseBody} among the values of an envelope (deleting its temporary file). */
    public static void release(Map<String, Object> envelope) {
        if (envelope == null) {
            return;
        }
        for (Object value : envelope.values()) {
            if (value instanceof ResponseBody body) {
                body.close();
            }
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // the sweep of abandoned files removes it later
        }
        OPEN_FILES.remove(path);
    }

    /** Deletes temporary files of ours older than {@code abandonedAfter} (left by a crash); once per directory. */
    static int sweep(Settings settings) {
        int deleted = 0;
        Path dir = settings.dir().toAbsolutePath();
        if (!Files.isDirectory(dir)) {
            return 0;
        }
        Instant cutoff = Instant.now().minus(settings.abandonedAfter());
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, FILE_PREFIX + "*" + FILE_SUFFIX)) {
            for (Path f : files) {
                try {
                    if (!OPEN_FILES.contains(f) && Files.getLastModifiedTime(f).toInstant().isBefore(cutoff)) {
                        Files.deleteIfExists(f);
                        deleted++;
                    }
                } catch (IOException ignored) {
                    // in use by another process or already gone
                }
            }
        } catch (IOException ignored) {
            // the directory cannot be listed; nothing to sweep
        }
        return deleted;
    }

    /** An output stream that keeps the first bytes in memory and moves to a temporary file when they exceed it. */
    static final class Writer extends OutputStream {
        private final Settings settings;
        private ByteArrayOutputStream memory = new ByteArrayOutputStream();
        private Path file;
        private OutputStream out;
        private long size;
        private long nextSpaceCheck;
        private boolean finished;

        Writer(Settings settings) {
            this.settings = settings;
        }

        long size() {
            return size;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            size += len;
            if (settings.maxBytes() > 0 && size > settings.maxBytes()) {
                throw new LocalLimitException("the response exceeded the local limit of " + mb(settings.maxBytes())
                        + " MB set by " + ENV_MAX_RESPONSE_MB + " (a setting of this service, not a CyberArk limit); "
                        + "nothing was returned. Raise or unset it, or request a smaller page");
            }
            if (out == null && size <= settings.memoryBytes()) {
                memory.write(b, off, len);
                return;
            }
            if (out == null) {
                startFile();
            }
            if (size >= nextSpaceCheck) {
                checkFreeSpace();
                nextSpaceCheck = size + FREE_SPACE_CHECK_EVERY;
            }
            out.write(b, off, len);
        }

        private void startFile() throws IOException {
            Path dir = settings.dir().toAbsolutePath();
            boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
            if (!Files.isDirectory(dir)) {
                if (posix) {
                    Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rwx------")));
                } else {
                    Files.createDirectories(dir);
                }
            }
            if (SWEPT_DIRS.add(dir)) {
                sweep(settings);
            }
            checkFreeSpace();
            FileAttribute<?>[] attrs = posix ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------"))} : new FileAttribute<?>[0];
            file = Files.createTempFile(dir, FILE_PREFIX, FILE_SUFFIX, attrs);
            OPEN_FILES.add(file);
            out = new java.io.BufferedOutputStream(Files.newOutputStream(file), 64 * 1024);
            memory.writeTo(out);
            memory = null;
        }

        private void checkFreeSpace() throws IOException {
            long free = Files.getFileStore(settings.dir().toAbsolutePath()).getUsableSpace();
            if (free - FREE_SPACE_CHECK_EVERY < settings.minFreeBytes()) {
                throw new LocalLimitException("free disk space in " + settings.dir().toAbsolutePath()
                        + " is down to " + mb(free) + " MB, below the reserve of " + mb(settings.minFreeBytes())
                        + " MB (" + ENV_MIN_FREE_MB + "; a setting of this service, not a CyberArk limit); the "
                        + "response was not kept. Free space, choose another " + ENV_DIR + ", or request a smaller page");
            }
        }

        /** The finished body; after this, closing the writer no longer deletes anything. */
        ResponseBody finish() throws IOException {
            if (out != null) {
                out.close();
            }
            finished = true;
            if (file == null) {
                return new ResponseBody(memory.toByteArray(), null, size);
            }
            return new ResponseBody(null, file, size);
        }

        /** Without {@link #finish()}: discards everything written (failure path). */
        @Override
        public void close() {
            if (finished) {
                return;
            }
            finished = true;
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ignored) {
                // deleted below
            }
            if (file != null) {
                deleteQuietly(file);
            }
            memory = null;
        }

        private static long mb(long bytes) {
            return bytes / (1024 * 1024);
        }
    }

    /**
     * Writes the body into the JSON being generated: as a JSON value copied in pieces (bytes unchanged, apart from a
     * leading byte-order mark, which would not be valid inside the envelope), or as a JSON string in text mode.
     */
    static final class Serializer extends StdSerializer<ResponseBody> {

        Serializer() {
            super(ResponseBody.class);
        }

        @Override
        public void serialize(ResponseBody body, JsonGenerator gen, SerializerProvider provider) throws IOException {
            try (Reader reader = new InputStreamReader(body.open(), StandardCharsets.UTF_8)) {
                if (body.text) {
                    gen.writeString(reader, -1);
                    return;
                }
                gen.writeRawValue("");
                char[] buf = new char[16 * 1024];
                int carry = 0;
                boolean first = true;
                int n;
                while ((n = reader.read(buf, carry, buf.length - carry)) != -1) {
                    int len = carry + n;
                    int start = 0;
                    if (first && len > 0) {
                        first = false;
                        if (buf[0] == '﻿') {
                            start = 1;
                        }
                    }
                    // never split a surrogate pair between two writes
                    int end = Character.isHighSurrogate(buf[len - 1]) ? len - 1 : len;
                    gen.writeRaw(buf, start, end - start);
                    carry = len - end;
                    if (carry > 0) {
                        buf[0] = buf[len - 1];
                    }
                }
                if (carry > 0) {
                    gen.writeRaw(buf, 0, carry);
                }
            }
        }
    }
}
