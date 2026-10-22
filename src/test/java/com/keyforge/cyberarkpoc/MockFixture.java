package com.keyforge.cyberarkpoc;

import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockDataset;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.time.Duration;

/** Starts a mock CyberArk on a free port with FABRICATED data and builds a client pointed at it. */
public final class MockFixture implements AutoCloseable {

    public final MockCyberArkServer mock;
    public final CyberArkClient client;

    private MockFixture(MockDataset data, String clientSecret) {
        try {
            mock = MockCyberArkServer.start(data, 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        client = new CyberArkClient(config(mock.rootUrl(), clientSecret));
    }

    public static MockFixture start(MockDataset data) {
        return new MockFixture(data, MockCyberArkServer.MOCK_CLIENT_SECRET);
    }

    public static MockFixture startWithSecret(MockDataset data, String clientSecret) {
        return new MockFixture(data, clientSecret);
    }

    /** Identity and policy calls under {@code /api}, as in the client mail. */
    public static CyberArkConfig config(String rootUrl, String clientSecret) {
        return new CyberArkConfig(
                URI.create(rootUrl + "/api"),
                URI.create(rootUrl + "/api"),
                URI.create(rootUrl + "/oauth2/platformtoken"),
                MockCyberArkServer.MOCK_CLIENT_ID,
                clientSecret,
                Duration.ofSeconds(5));
    }

    @Override
    public void close() {
        mock.close();
    }
}
