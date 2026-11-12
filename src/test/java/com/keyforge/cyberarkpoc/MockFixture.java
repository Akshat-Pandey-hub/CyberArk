package com.keyforge.cyberarkpoc;

import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.client.PolicyClient;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;
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

    /** Identity calls under {@code /api}, as in the client mail. */
    public static CyberArkConfig config(String rootUrl, String clientSecret) {
        return new CyberArkConfig(
                URI.create(rootUrl + "/api"),
                URI.create(rootUrl + "/oauth2/platformtoken"),
                MockCyberArkServer.MOCK_CLIENT_ID,
                clientSecret,
                Duration.ofSeconds(5));
    }

    /** A policy client for this mock: UAP at {@code /api}, SCA at {@code /sca/api}, the mock's custom OAuth2 app. */
    public PolicyClient policyClient(PolicyConfig.Api api) {
        return new PolicyClient(policyConfig(mock.rootUrl(), api, MockCyberArkServer.MOCK_CLIENT_SECRET,
                PolicyConfig.MAX_PAGE_SIZE, PolicyConfig.DEFAULT_MAX_PAGES));
    }

    public static PolicyConfig policyConfig(String rootUrl, PolicyConfig.Api api, String clientSecret, int pageSize,
                                            int maxPages) {
        return new PolicyConfig(api,
                URI.create(rootUrl + (api == PolicyConfig.Api.SCA ? "/sca/api" : "/api")),
                URI.create(rootUrl + PolicyConfig.TOKEN_PATH + MockCyberArkServer.MOCK_POLICY_APP_ID),
                MockCyberArkServer.MOCK_CLIENT_ID, clientSecret, pageSize, maxPages, Duration.ofSeconds(5));
    }

    @Override
    public void close() {
        mock.close();
    }
}
