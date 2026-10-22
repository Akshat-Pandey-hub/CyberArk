package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/** Shared JSON helpers. */
final class Json {

    static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    static JsonNode parse(String endpoint, int httpStatus, String body) {
        try {
            JsonNode node = MAPPER.readTree(body);
            if (node == null || node.isMissingNode()) {
                throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, httpStatus,
                        "empty body");
            }
            return node;
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, httpStatus,
                    "body is not JSON: " + snippet(body), e);
        }
    }

    /** The field as text, or {@code null} when it is absent or JSON null. */
    static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    /**
     * A short, safe excerpt of a response body for an error message. A JSON body is first passed through
     * {@link SecretRedactor}; any body is then cleaned by {@link ErrorSanitizer}. Raw secrets never reach the
     * message.
     */
    static String snippet(String body) {
        if (body == null) {
            return "";
        }
        String text;
        try {
            JsonNode node = MAPPER.readTree(body);
            text = node == null || node.isMissingNode() ? body : SecretRedactor.redact(node).value().toString();
        } catch (IOException | RuntimeException e) {
            text = body;
        }
        String flat = ErrorSanitizer.clean(text.replaceAll("\\s+", " ").trim());
        return flat.length() <= 300 ? flat : flat.substring(0, 300) + "...";
    }
}
