package com.keyforge.cyberarkpoc.store;

import com.keyforge.cyberarkpoc.config.ConfigException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Destination PostgreSQL settings: {@code PG_HOST}, {@code PG_PORT} (5432), {@code PG_DATABASE},
 * {@code PG_USERNAME}, {@code PG_PASSWORD}, {@code PG_DEST_SCHEMA} (default {@value #DEFAULT_SCHEMA}).
 */
public record DbConfig(String host, int port, String database, String username, String password, String schema) {

    /** Schema for the CyberArk tables unless {@code PG_DEST_SCHEMA} says otherwise. */
    public static final String DEFAULT_SCHEMA = "cyberark";

    public DbConfig {
        schema = validateSchema(schema == null || schema.isBlank() ? DEFAULT_SCHEMA : schema.trim());
    }

    public static DbConfig fromEnvironment(Map<String, String> env) {
        List<String> missing = new ArrayList<>();
        String host = required(env, "PG_HOST", missing);
        String database = required(env, "PG_DATABASE", missing);
        String username = required(env, "PG_USERNAME", missing);
        String password = required(env, "PG_PASSWORD", missing);
        if (!missing.isEmpty()) {
            throw new ConfigException("Missing required database configuration: " + String.join(", ", missing));
        }
        String portText = env.get("PG_PORT");
        int port = 5432;
        if (portText != null && !portText.isBlank()) {
            try {
                port = Integer.parseInt(portText.trim());
            } catch (NumberFormatException e) {
                throw new ConfigException("PG_PORT must be an integer but was: " + portText);
            }
        }
        return new DbConfig(host.trim(), port, database.trim(), username, password, env.get("PG_DEST_SCHEMA"));
    }

    public String jdbcUrl() {
        return "jdbc:postgresql://" + host + ":" + port + "/" + database;
    }

    /** Opens a plain JDBC connection, as Part 2's {@code PostgresConnection} does (no pooling). */
    public Connection open() throws SQLException {
        return DriverManager.getConnection(jdbcUrl(), username, password);
    }

    /** Part 2's {@code SchemaName} rule: a plain, unquoted PostgreSQL identifier. */
    static String validateSchema(String schema) {
        if (!schema.matches("[A-Za-z_][A-Za-z0-9_]{0,62}")) {
            throw new ConfigException("PG_DEST_SCHEMA must be a plain identifier ([A-Za-z_][A-Za-z0-9_]*) but was: "
                    + schema);
        }
        return schema;
    }

    private static String required(Map<String, String> env, String key, List<String> missing) {
        String v = env.get(key);
        if (v == null || v.isBlank()) {
            missing.add(key);
            return null;
        }
        return v;
    }

    /** Never prints the password. */
    @Override
    public String toString() {
        return "DbConfig[" + jdbcUrl() + ", user=" + username + ", password=***, schema=" + schema + "]";
    }
}
