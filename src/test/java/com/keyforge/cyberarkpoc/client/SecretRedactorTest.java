package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretRedactorTest {

    private static JsonNode json(String text) {
        return Json.parse("test", 200, text);
    }

    @Test
    void removesTheSecretFieldOfTheDocumentedAccountShapeAndKeepsMetadata() {
        // Structure of the official "Get accounts" result example (values fabricated).
        JsonNode accounts = json("""
                {"value": [{"id": "1_2", "name": "acc", "secretType": "password", "secret": "S3cr3t!",
                  "platformAccountProperties": {"Location": "IT"},
                  "secretManagement": {"automaticManagementEnabled": true, "status": "Success"}}],
                 "count": 1}""");

        SecretRedactor.Redacted result = SecretRedactor.redact(accounts);
        JsonNode account = result.value().get("value").get(0);

        assertEquals(1, result.removedFields());
        assertFalse(account.has("secret"));
        assertEquals("password", account.get("secretType").asText());
        assertEquals("Success", account.get("secretManagement").get("status").asText());
        assertEquals("IT", account.get("platformAccountProperties").get("Location").asText());
        assertFalse(result.value().toString().contains("S3cr3t!"));
    }

    @Test
    void removesAtAnyDepthAndInAnyLetterCase() {
        JsonNode node = json("""
                {"a": {"Secret": "x", "b": [{"PASSWORD": "y", "keep": 1}, {"nested": {"secret": "z"}}]}}""");

        SecretRedactor.Redacted result = SecretRedactor.redact(node);

        assertEquals(3, result.removedFields());
        String text = result.value().toString();
        assertFalse(text.contains("\"x\"") || text.contains("\"y\"") || text.contains("\"z\""));
        assertTrue(text.contains("keep"));
    }

    @Test
    void doesNotChangeTheInputOrUnrelatedFields() {
        JsonNode node = json("{\"secret\": \"x\", \"PasswordLength\": 12}");

        SecretRedactor.Redacted result = SecretRedactor.redact(node);

        assertTrue(node.has("secret"), "input untouched");
        assertEquals(12, result.value().get("PasswordLength").asInt(), "only exact names are removed");
    }
}
