package com.keyforge.cyberarkpoc.client;

import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cleans error text before it is returned through REST, stored in the run log, or printed.
 *
 * <ul>
 *   <li>Known sensitive values (the vault password, session tokens, client secrets) are replaced with {@code ***}.</li>
 *   <li>Values after {@code password}, {@code secret}, {@code newPassword}, {@code client_secret},
 *       {@code access_token} or {@code token} (as JSON fields, {@code key=value} or {@code key: value}) are masked.</li>
 *   <li>{@code Authorization} header values and {@code Bearer} tokens are masked.</li>
 *   <li>The result is cut to {@value #MAX_LENGTH} characters.</li>
 * </ul>
 */
public final class ErrorSanitizer {

    public static final int MAX_LENGTH = 500;
    static final String MASK = "***";

    private static final Pattern KEY_VALUE = Pattern.compile(
            "(?i)(\"?\\b(?:password|newpassword|secret|client_secret|access_token|token)\\b\"?\\s*[:=]\\s*)"
                    + "(\"(?:[^\"\\\\]|\\\\.)*\"|[^\\s,;&}\\]]+)");
    /** The header value including an optional scheme ("Bearer x", "Basic x"), so the credential is always covered. */
    private static final Pattern AUTHORIZATION = Pattern.compile(
            "(?i)(authorization\"?\\s*[:=]\\s*)(\"[^\"]*\"|(?:(?:bearer|basic|negotiate|ntlm)\\s+)?[^\\s\",;}]+)");
    private static final Pattern BEARER = Pattern.compile("(?i)\\bbearer\\s+[A-Za-z0-9._~+/=-]+");

    private ErrorSanitizer() {
    }

    public static String clean(String text) {
        return clean(text, List.of());
    }

    public static String clean(String text, Collection<String> sensitiveValues) {
        if (text == null) {
            return null;
        }
        String out = text;
        for (String value : sensitiveValues) {
            if (value != null && value.length() >= 4) {
                out = out.replace(value, MASK);
            }
        }
        out = BEARER.matcher(out).replaceAll("Bearer " + MASK);
        out = replaceKeepingKey(KEY_VALUE, out);
        out = replaceKeepingKey(AUTHORIZATION, out);
        return out.length() <= MAX_LENGTH ? out : out.substring(0, MAX_LENGTH) + "...";
    }

    private static String replaceKeepingKey(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String value = m.group(2);
            String masked = value.startsWith("\"") ? "\"" + MASK + "\"" : MASK;
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + masked));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
