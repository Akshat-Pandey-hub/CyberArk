package com.keyforge.cyberarkpoc.rest;

import com.keyforge.cyberarkpoc.client.CloudApi;
import com.keyforge.cyberarkpoc.client.ResponseBody;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The four cloud pass-through routes ({@link CloudApi}). Settings are read from the environment on every call, so a
 * configuration error is reported in that call's JSON. Unknown query parameters are rejected (HTTP 400) so that a
 * misspelt {@code pagesize} is never silently ignored.
 *
 * <pre>
 * GET cloud/token?target=identity|policies
 * GET cloud/redrock?script=&lt;SQL&gt;[&amp;pageNumber=1&amp;pageSize=2&amp;limit=..&amp;caching=..]
 * GET cloud/role?id=&lt;role UUID&gt;[&amp;SuppressPrincipalsList=true|false&amp;getRights=true|false]
 * GET cloud/policies?limit=2[&amp;nextToken=..&amp;filter=..&amp;q=..&amp;sort=..]   (uap)
 * GET cloud/policies[?cloud_provider=..&amp;free_text=..&amp;status=..&amp;debug=..]    (sca)
 * </pre>
 *
 * Every value is passed to CyberArk as given; CyberArk does the filtering, sorting and paging. Redrock's query comes
 * from {@code script}, else {@value #ENV_REDROCK_SCRIPT}, else (backward compatibility) the client mail's approver-role
 * query built from {@value #ENV_ROLE_PATTERN}. {@code Caching} comes from {@code caching}, else
 * {@value #ENV_REDROCK_CACHING} ({@code none} = do not send it), else -1 (documented: live data).
 */
public final class CloudRoutes {

    public static final String TOKEN = "cloud/token";
    public static final String REDROCK = "cloud/redrock";
    public static final String ROLE = "cloud/role";
    public static final String POLICIES = "cloud/policies";

    /** The approver-role pattern from the client mail; {@value #ENV_ROLE_PATTERN} overrides it. */
    public static final String DEFAULT_ROLE_PATTERN = "APP-CYA-ISPSS-SCA-AWS-%-BUApprovers";
    public static final String ENV_ROLE_PATTERN = "CYBERARK_APPROVER_ROLE_PATTERN";
    /** A default Redrock query for calls without {@code script}. */
    public static final String ENV_REDROCK_SCRIPT = "CYBERARK_REDROCK_SCRIPT";
    public static final String ENV_REDROCK_CACHING = "CYBERARK_REDROCK_CACHING";
    public static final int DEFAULT_CACHING = -1;

    private CloudRoutes() {
    }

    public static Map<String, ExtractionRestServer.QueryRoute> routes(Supplier<Map<String, String>> environment) {
        Map<String, ExtractionRestServer.QueryRoute> routes = new LinkedHashMap<>();
        routes.put(TOKEN, new ExtractionRestServer.QueryRoute(
                "Login test: requests a token with the configured method (target=identity|policies); the token is "
                        + "never returned",
                p -> {
                    allow(p, "target");
                    Map<String, String> env = environment.get();
                    String target = p.getOrDefault("target", "identity").trim().toLowerCase(java.util.Locale.ROOT);
                    return switch (target) {
                        case "identity" -> new CloudApi(CyberArkConfig.fromEnvironment(env), null)
                                .token(CloudApi.Target.IDENTITY);
                        case "policies" -> new CloudApi(null, PolicyConfig.fromEnvironment(env))
                                .token(CloudApi.Target.POLICIES);
                        default -> throw new IllegalArgumentException("target must be 'identity' or 'policies'");
                    };
                }));
        routes.put(REDROCK, new ExtractionRestServer.QueryRoute(
                "POST <identity>/Redrock/query with the given query (script), one page (pageNumber, pageSize, "
                        + "optional limit, caching); CyberArk's response as received",
                p -> {
                    allow(p, "script", "pageNumber", "pageSize", "limit", "caching");
                    Map<String, String> env = environment.get();
                    return new CloudApi(CyberArkConfig.fromEnvironment(env), null).withSpool(spool(env))
                            .redrock(script(p, env),
                            integer(p, "pageNumber"), integer(p, "pageSize"), integer(p, "limit"), caching(p, env));
                }));
        routes.put(ROLE, new ExtractionRestServer.QueryRoute(
                "POST <identity>/Roles/GetRole?Name=<id> (id = role UUID; optional SuppressPrincipalsList, getRights "
                        + "= true|false as documented); CyberArk's response as received",
                p -> {
                    allow(p, "id", "SuppressPrincipalsList", "getRights");
                    Map<String, String> env = environment.get();
                    return new CloudApi(CyberArkConfig.fromEnvironment(env), null).withSpool(spool(env))
                            .role(p.get("id"), bool(p, "SuppressPrincipalsList"), bool(p, "getRights"));
                }));
        routes.put(POLICIES, new ExtractionRestServer.QueryRoute(
                "GET <uap>/policies, one page (limit 1-50, optional nextToken from the previous answer, optional "
                        + "filter, q, sort as documented); for the SCA API: optional cloud_provider, free_text, status, "
                        + "debug as documented; CyberArk's response as received",
                p -> {
                    allow(p, "limit", "nextToken", "filter", "q", "sort", "cloud_provider", "free_text", "status",
                            "debug");
                    Map<String, String> env = environment.get();
                    return new CloudApi(null, PolicyConfig.fromEnvironment(env)).withSpool(spool(env))
                            .policies(integer(p, "limit"), p.get("nextToken"), p.get("filter"), p.get("q"),
                                    p.get("sort"), p.get("cloud_provider"), p.get("free_text"), p.get("status"),
                                    p.get("debug"));
                }));
        return routes;
    }

    /** {@code script}, else the configured default query, else the approver-role query (backward compatibility). */
    static String script(Map<String, String> params, Map<String, String> env) {
        String script = params.get("script");
        if (script != null && !script.isBlank()) {
            return script;
        }
        String configured = env.get(ENV_REDROCK_SCRIPT);
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        String pattern = env.get(ENV_ROLE_PATTERN);
        return CloudApi.approverRoleScript(pattern == null || pattern.isBlank() ? DEFAULT_ROLE_PATTERN : pattern);
    }

    /** {@code caching}, else {@value #ENV_REDROCK_CACHING} ({@code none} = not sent), else -1. */
    static Integer caching(Map<String, String> params, Map<String, String> env) {
        Integer given = integer(params, "caching");
        if (given != null) {
            return given;
        }
        String configured = env.get(ENV_REDROCK_CACHING);
        if (configured == null || configured.isBlank()) {
            return DEFAULT_CACHING;
        }
        if (configured.trim().equalsIgnoreCase("none")) {
            return null;
        }
        try {
            return Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            throw new com.keyforge.cyberarkpoc.config.ConfigException(ENV_REDROCK_CACHING
                    + " must be a whole number or 'none' but was: " + configured);
        }
    }

    private static void allow(Map<String, String> params, String... names) {
        Set<String> allowed = Set.of(names);
        for (String key : params.keySet()) {
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("unknown parameter '" + key + "'; allowed: " + String.join(", ", names));
            }
        }
    }

    /** Where large response bodies are kept ({@code CYBERARK_SPOOL_DIR} etc., see {@link ResponseBody.Settings}). */
    static ResponseBody.Settings spool(Map<String, String> env) {
        return ResponseBody.Settings.fromEnvironment(env);
    }

    private static Boolean bool(Map<String, String> params, String name) {
        String value = params.get(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "true" -> Boolean.TRUE;
            case "false" -> Boolean.FALSE;
            default -> throw new IllegalArgumentException(name + " must be true or false but was: " + value);
        };
    }

    private static Integer integer(Map<String, String> params, String name) {
        String value = params.get(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be a whole number but was: " + value);
        }
    }
}
