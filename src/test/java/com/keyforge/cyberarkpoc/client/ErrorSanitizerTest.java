package com.keyforge.cyberarkpoc.client;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ErrorSanitizerTest {

    @Test
    void masksKnownSensitiveValuesAnywhere() {
        String out = ErrorSanitizer.clean("logon failed for token tok-123456 and pw S3cr3tPw!",
                List.of("tok-123456", "S3cr3tPw!"));

        assertFalse(out.contains("tok-123456"));
        assertFalse(out.contains("S3cr3tPw!"));
        assertTrue(out.contains("***"));
    }

    @Test
    void masksSecretLikeFieldsInJsonAndText() {
        String out = ErrorSanitizer.clean("{\"secret\":\"abc\",\"Password\": \"p w\",\"name\":\"keep\"} "
                + "password=hunter2; client_secret: xyz access_token=a.b.c");

        assertFalse(out.contains("abc") || out.contains("p w") || out.contains("hunter2") || out.contains("xyz")
                || out.contains("a.b.c"), out);
        assertTrue(out.contains("\"name\":\"keep\""), "other fields stay readable");
        assertTrue(out.contains("\"secret\":\"***\""));
    }

    @Test
    void masksAuthorizationHeadersAndBearerTokens() {
        String out = ErrorSanitizer.clean("Authorization: abcdef123 then Bearer eyJhbGciOi.payload.sig");

        assertFalse(out.contains("abcdef123"));
        assertFalse(out.contains("eyJhbGciOi"));
    }

    @Test
    void masksTheCredentialAfterAnAuthorizationScheme() {
        // Regression: "Authorization: Bearer <token>" once masked only the word "Bearer".
        for (String header : new String[] {"Authorization: Bearer TOKEN-AAA", "authorization=Basic TOKEN-AAA",
                "\"Authorization\":\"TOKEN-AAA\"", "Authorization: TOKEN-AAA"}) {
            assertFalse(ErrorSanitizer.clean(header).contains("TOKEN-AAA"), header + " -> "
                    + ErrorSanitizer.clean(header));
        }
    }

    @Test
    void cutsLongTextAndAcceptsNull() {
        assertNull(ErrorSanitizer.clean(null));
        assertEquals(ErrorSanitizer.MAX_LENGTH + 3, ErrorSanitizer.clean("x".repeat(2000)).length());
    }

    @Test
    void responseSnippetsAreRedactedJsonOrCleanText() {
        String json = Json.snippet("{\"ErrorCode\":\"E1\",\"secret\":\"VALUE-1\",\"nested\":{\"password\":\"VALUE-2\"}}");
        String text = Json.snippet("<html>error password=VALUE-3</html>");

        assertTrue(json.contains("E1"));
        assertFalse(json.contains("VALUE-1") || json.contains("VALUE-2"), json);
        assertFalse(text.contains("VALUE-3"), text);
    }
}
