package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Removes secret values from a CyberArk response before it is returned or stored.
 *
 * <p>The official "Get accounts" result lists a {@code secret} field. Any object field named
 * {@code secret} or {@code password} (any letter case, at any depth) is removed. Metadata about the secret,
 * such as {@code secretType} and {@code secretManagement}, is kept because its name is not one of those.
 */
public final class SecretRedactor {

    /** Field names whose values are removed (compared case-insensitively). */
    public static final Set<String> SECRET_FIELDS = Set.of("secret", "password");

    /** The redacted copy and how many fields were removed. */
    public record Redacted(JsonNode value, int removedFields) {
    }

    private SecretRedactor() {
    }

    public static Redacted redact(JsonNode node) {
        if (node == null) {
            return new Redacted(null, 0);
        }
        JsonNode copy = node.deepCopy();
        int removed = strip(copy);
        return new Redacted(copy, removed);
    }

    private static int strip(JsonNode node) {
        int removed = 0;
        if (node instanceof ObjectNode object) {
            List<String> drop = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (SECRET_FIELDS.contains(field.getKey().toLowerCase(Locale.ROOT))) {
                    drop.add(field.getKey());
                } else {
                    removed += strip(field.getValue());
                }
            }
            drop.forEach(object::remove);
            removed += drop.size();
        } else if (node != null && node.isArray()) {
            for (JsonNode item : node) {
                removed += strip(item);
            }
        }
        return removed;
    }
}
