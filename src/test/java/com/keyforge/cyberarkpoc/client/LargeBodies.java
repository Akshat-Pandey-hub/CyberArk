package com.keyforge.cyberarkpoc.client;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Deterministic large response bodies written straight to a stream (never held in memory whole), and a raw socket
 * server for bodies that are cut off mid-way. FABRICATED data in the documented shapes.
 */
public final class LargeBodies {

    private LargeBodies() {
    }

    /** A Redrock answer with {@code rows} rows (~230 bytes each), FullCount = rows. */
    public static void redrock(OutputStream out, int rows) throws IOException {
        write(out, "{\"success\":true,\"Result\":{\"IsAggregate\":false,\"Count\":" + rows + ",\"FullCount\":" + rows
                + ",\"Columns\":[{\"Name\":\"ID\"},{\"Name\":\"Name\"}],\"Results\":[");
        StringBuilder b = new StringBuilder(512);
        for (int i = 0; i < rows; i++) {
            b.setLength(0);
            if (i > 0) {
                b.append(',');
            }
            b.append("{\"Entities\":[{\"Type\":\"Role\",\"Key\":\"role-").append(i)
                    .append("\",\"IsForeignKey\":false}],\"Row\":{\"ID\":\"role-").append(i)
                    .append("\",\"Name\":\"MOCK-ROLE-").append(i).append("-BUApprovers\",\"Ratio\":1.10,")
                    .append("\"Big\":12345678901234567890,\"Description\":\"MOCK approver group ").append(i)
                    .append(" café \\u00e9 \\ud83d\\ude00\"}}");
            write(out, b.toString());
        }
        write(out, "],\"ReturnID\":\"\"},\"Message\":null,\"MessageID\":null,\"Exception\":null,\"ErrorID\":null,"
                + "\"ErrorCode\":null,\"IsSoftError\":false,\"InnerExceptions\":null}");
    }

    /** A GetRole answer with {@code principals} entries and one description of {@code descriptionChars} characters. */
    public static void role(OutputStream out, int principals, int descriptionChars) throws IOException {
        write(out, "{\"success\":true,\"Result\":{\"Uuid\":\"role-big\",\"Name\":\"MOCK-BIG\",\"Description\":\"");
        byte[] chunk = "abcdefghij".repeat(1000).getBytes(StandardCharsets.UTF_8);
        for (int left = descriptionChars; left > 0; left -= chunk.length) {
            out.write(chunk, 0, Math.min(chunk.length, left));
        }
        write(out, "\",\"RoleType\":\"PrincipalList\",\"ReadOnly\":false,\"Principals\":[");
        for (int i = 0; i < principals; i++) {
            write(out, (i > 0 ? "," : "") + "\"u=mock.user" + i + "@example.invalid\"");
        }
        write(out, "]},\"Message\":null}");
    }

    public static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-256 of everything written to it; keeps nothing. */
    public static final class Digest extends OutputStream {
        private final MessageDigest md;
        private long size;

        public Digest() {
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void write(int b) {
            md.update((byte) b);
            size++;
        }

        @Override
        public void write(byte[] b, int off, int len) {
            md.update(b, off, len);
            size += len;
        }

        public long size() {
            return size;
        }

        public String hex() {
            return HexFormat.of().formatHex(md.digest());
        }
    }

    private static void write(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Answers every connection with the given raw bytes (status line, headers and a partial body) and then closes the
     * socket: a response that is interrupted mid-way.
     */
    public static final class CutOffServer implements AutoCloseable {
        private final ServerSocket socket;

        public CutOffServer(String rawResponse) throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread t = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (Socket s = socket.accept()) {
                        byte[] buf = new byte[8192];
                        int n;
                        StringBuilder head = new StringBuilder();
                        while ((n = s.getInputStream().read(buf)) > 0) {
                            head.append(new String(buf, 0, n, StandardCharsets.ISO_8859_1));
                            int end = head.indexOf("\r\n\r\n");
                            if (end >= 0) {
                                int length = contentLength(head.substring(0, end));
                                if (head.length() - end - 4 >= length) {
                                    break;
                                }
                            }
                        }
                        s.getOutputStream().write(rawResponse.getBytes(StandardCharsets.UTF_8));
                        s.getOutputStream().flush();
                    } catch (IOException ignored) {
                        // closed
                    }
                }
            }, "cut-off-server");
            t.setDaemon(true);
            t.start();
        }

        private static int contentLength(String head) {
            for (String line : head.split("\r\n")) {
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                    return Integer.parseInt(line.substring(15).trim());
                }
            }
            return 0;
        }

        public String rootUrl() {
            return "http://127.0.0.1:" + socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
