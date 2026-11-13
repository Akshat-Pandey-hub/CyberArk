package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One streaming pass over a response body, without building it in memory: checks that it is JSON, detects duplicate
 * keys, looks for this service's own secrets in every string and field name, counts the elements of the arrays named
 * by the caller (e.g. {@code /Result/Results}) and captures the scalar values named by the caller (e.g.
 * {@code /Result/FullCount}). Memory use is bounded by the largest single value and the deepest object, not by the
 * body size.
 */
final class ResponseInspector {

    /** The nesting depth Jackson allows by default; deeper JSON is reported as {@code PARSER_LIMIT}. */
    static final int MAX_NESTING = StreamReadConstraints.DEFAULT_MAX_DEPTH;

    /** Streaming parser: no limit on string or number length (they are not held as a tree), default nesting. */
    private static final JsonFactory FACTORY = JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxStringLength(Integer.MAX_VALUE)
                    .maxNumberLength(Integer.MAX_VALUE)
                    .maxNameLength(Integer.MAX_VALUE)
                    .maxNestingDepth(MAX_NESTING)
                    .build())
            .build();

    private static final JsonNodeFactory NODES = JsonNodeFactory.withExactBigDecimals(true);
    /** Paths are only built near the top of the document, where all watched paths are. */
    private static final int PATH_DEPTH = 4;

    enum Outcome { JSON, DUPLICATE_KEYS, NOT_JSON, PARSER_LIMIT }

    record Result(Outcome outcome, String error, boolean secretFound, Map<String, Long> counts,
                  Map<String, JsonNode> values) {

        Long count(String path) {
            return counts.get(path);
        }

        JsonNode value(String path) {
            return values.get(path);
        }
    }

    private ResponseInspector() {
    }

    static Result inspect(ResponseBody body, Set<String> countPaths, Set<String> valuePaths, List<String> secrets)
            throws IOException {
        Result strict = pass(body, countPaths, valuePaths, secrets, true);
        if (strict.outcome() != Outcome.DUPLICATE_KEYS) {
            return strict;
        }
        // Valid JSON with a repeated key: count and look for secrets once more without the duplicate check.
        Result lenient = pass(body, countPaths, valuePaths, secrets, false);
        return new Result(lenient.outcome() == Outcome.JSON ? Outcome.DUPLICATE_KEYS : lenient.outcome(),
                strict.error(), lenient.secretFound(), lenient.counts(), lenient.values());
    }

    private static final class Frame {
        final boolean array;
        final String path; // null below PATH_DEPTH
        final boolean counted;
        String field;
        int index;

        Frame(boolean array, String path, boolean counted) {
            this.array = array;
            this.path = path;
            this.counted = counted;
        }
    }

    private static Result pass(ResponseBody body, Set<String> countPaths, Set<String> valuePaths,
                               List<String> secrets, boolean strict) throws IOException {
        Map<String, Long> counts = new HashMap<>();
        Map<String, JsonNode> values = new HashMap<>();
        countPaths.forEach(p -> counts.put(p, null));
        boolean secretFound = false;
        boolean rootDone = false;
        List<Frame> stack = new ArrayList<>();
        try (InputStream in = body.open(); JsonParser p = FACTORY.createParser(in)) {
            if (strict) {
                p.enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION.mappedFeature());
            }
            JsonToken token;
            while ((token = p.nextToken()) != null) {
                if (rootDone) {
                    // a JSON document is exactly one value; a second one would make the envelope invalid if copied
                    return new Result(Outcome.NOT_JSON, "more than one JSON value in the body (the second starts at "
                            + "byte " + p.currentTokenLocation().getByteOffset() + ")", secretFound, counts, values);
                }
                if (token == JsonToken.FIELD_NAME) {
                    stack.get(stack.size() - 1).field = p.currentName();
                    secretFound |= containsSecret(p.currentName(), secrets);
                    continue;
                }
                if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                    stack.remove(stack.size() - 1);
                    rootDone = stack.isEmpty();
                    continue;
                }
                // a value: work out its path (only near the top) and count it in its parent array
                String path = "";
                if (!stack.isEmpty()) {
                    Frame parent = stack.get(stack.size() - 1);
                    if (parent.array) {
                        if (parent.counted) {
                            counts.merge(parent.path, 1L, Long::sum);
                        }
                        path = parent.path == null ? null : parent.path + "/" + parent.index;
                        parent.index++;
                    } else {
                        path = parent.path == null ? null : parent.path + "/" + parent.field;
                    }
                }
                if (path != null && stack.size() >= PATH_DEPTH) {
                    path = null;
                }
                if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                    boolean array = token == JsonToken.START_ARRAY;
                    boolean counted = array && path != null && countPaths.contains(path);
                    if (counted) {
                        counts.put(path, 0L);
                    }
                    stack.add(new Frame(array, path, counted));
                    continue;
                }
                if (token == JsonToken.VALUE_STRING) {
                    secretFound |= containsSecret(p.getText(), secrets);
                }
                if (path != null && valuePaths.contains(path)) {
                    values.put(path, scalar(p, token));
                }
                rootDone = stack.isEmpty(); // a scalar that is the whole document
            }
        } catch (StreamConstraintsException e) {
            return new Result(Outcome.PARSER_LIMIT, "the JSON exceeds a limit of the JSON parser of this service (not "
                    + "a CyberArk limit): " + e.getOriginalMessage(), secretFound, counts, values);
        } catch (JsonParseException e) {
            String message = e.getOriginalMessage();
            if (strict && message != null && message.startsWith("Duplicate field")) {
                return new Result(Outcome.DUPLICATE_KEYS, message, secretFound, counts, values);
            }
            return new Result(Outcome.NOT_JSON, message, secretFound, counts, values);
        }
        return new Result(Outcome.JSON, null, secretFound, counts, values);
    }

    private static JsonNode scalar(JsonParser p, JsonToken token) throws IOException {
        return switch (token) {
            case VALUE_STRING -> NODES.textNode(p.getText());
            case VALUE_TRUE -> NODES.booleanNode(true);
            case VALUE_FALSE -> NODES.booleanNode(false);
            case VALUE_NUMBER_INT -> NODES.numberNode(p.getBigIntegerValue());
            case VALUE_NUMBER_FLOAT -> NODES.numberNode(p.getDecimalValue());
            default -> NODES.nullNode();
        };
    }

    private static boolean containsSecret(String text, List<String> secrets) {
        if (text == null) {
            return false;
        }
        for (String s : secrets) {
            if (text.contains(s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A copy of the body in which every string and field name containing one of our secrets has the secret replaced
     * by {@code ***}. Written token by token (values exact; whitespace and escapes may differ from the original),
     * into a new {@link ResponseBody}, so it is never held in memory as a whole.
     */
    static ResponseBody maskedCopy(ResponseBody body, List<String> secrets, ResponseBody.Settings settings)
            throws IOException {
        try (ResponseBody.Writer writer = new ResponseBody.Writer(settings)) {
            try (InputStream in = body.open(); JsonParser p = FACTORY.createParser(in);
                 JsonGenerator g = FACTORY.createGenerator(writer)) {
                g.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
                JsonToken token;
                while ((token = p.nextToken()) != null) {
                    if (token == JsonToken.FIELD_NAME) {
                        g.writeFieldName(mask(p.currentName(), secrets));
                    } else if (token == JsonToken.VALUE_STRING) {
                        g.writeString(mask(p.getText(), secrets));
                    } else {
                        g.copyCurrentEventExact(p);
                    }
                }
            }
            return writer.finish();
        }
    }

    private static String mask(String text, List<String> secrets) {
        String result = text;
        for (String s : secrets) {
            result = result.replace(s, CloudApi.MASK);
        }
        return result;
    }
}
