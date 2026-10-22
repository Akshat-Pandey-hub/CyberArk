package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.check.ApproverGroupRun;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.store.GenericRecordStore.Kind;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.keyforge.cyberarkpoc.store.GenericRecordStore.join;
import static com.keyforge.cyberarkpoc.store.GenericRecordStore.kindOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Type, naming and SQL rules of the stores, without a database. */
class StoreSqlTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Kind kind(String json) throws Exception {
        return kindOf(MAPPER.readTree(json));
    }

    @Test
    void valueTypesFollowTheJsonValue() throws Exception {
        assertEquals(Kind.BOOLEAN, kind("true"));
        assertEquals(Kind.BIGINT, kind("1700000000000000101"));
        assertEquals(Kind.NUMERIC, kind("1.5"));
        assertEquals(Kind.NUMERIC, kind("123456789012345678901234567890"), "beyond bigint");
        assertEquals(Kind.TEXT, kind("\"123\""), "a numeric-looking string stays text");
        assertEquals(Kind.JSONB, kind("{\"a\": 1}"));
        assertEquals(Kind.JSONB, kind("[1, 2]"));
        assertNull(kind("null"));
        assertNull(kindOf(null), "a missing field has no type");
    }

    @Test
    void conflictingTypesWidenToATypeThatHoldsBoth() {
        assertEquals(Kind.BIGINT, join(null, Kind.BIGINT));
        assertEquals(Kind.NUMERIC, join(Kind.BIGINT, Kind.NUMERIC));
        assertEquals(Kind.TEXT, join(Kind.BIGINT, Kind.BOOLEAN));
        assertEquals(Kind.TEXT, join(Kind.NUMERIC, Kind.TEXT));
        assertEquals(Kind.JSONB, join(Kind.TEXT, Kind.JSONB));
        assertEquals(Kind.JSONB, join(Kind.JSONB, Kind.BOOLEAN));
        for (Kind a : Kind.values()) {
            for (Kind b : Kind.values()) {
                assertEquals(join(a, b), join(b, a), "join is symmetric");
            }
        }
    }

    @Test
    void namesAreKeptExactlyAndOnlyUnusableOnesGoToExtraFields() {
        assertEquals("\"safeName\"", GenericRecordStore.quote("safeName"));
        assertEquals("\"a\"\"b\"", GenericRecordStore.quote("a\"b"), "embedded quote doubled, name unchanged");
        assertTrue(GenericRecordStore.columnable("PlatformID"));
        assertTrue(GenericRecordStore.columnable("platformID"), "a different casing is a different column");
        assertFalse(GenericRecordStore.columnable(""));
        assertFalse(GenericRecordStore.columnable("x".repeat(64)), "over PostgreSQL's 63-byte limit");
        assertFalse(GenericRecordStore.columnable("record_uuid"), "a service column");
        assertFalse(GenericRecordStore.columnable("extracted_at"));
    }

    @Test
    void storeNamesAreValidated() {
        assertThrows(ConfigException.class, () -> new GenericRecordStore("bad-name", "pvwa_safe", List.of("safeUrlId")));
        assertThrows(IllegalArgumentException.class, () -> new GenericRecordStore("s", "Pvwa Safe", List.of("safeUrlId")));
        assertThrows(IllegalArgumentException.class, () -> new GenericRecordStore("s", "pvwa_safe", List.of()));
        assertThrows(IllegalArgumentException.class, () -> new GenericRecordStore("s", "pvwa_safe", List.of("record_uuid")));
        assertEquals("cyberark.pvwa_safe", new GenericRecordStore("cyberark", "pvwa_safe", List.of("safeUrlId")).table());
    }

    @Test
    void theFixedColumnStoreForTheIdentityUseCaseKeepsItsCompositeKey() {
        RawRecordRepository members = new RawRecordRepository("cyberark", "ispss_role_member",
                ApproverGroupRun.ROLE_MEMBER_COLUMNS, List.of("role_id", "Guid"));

        assertTrue(members.createTableSql().contains("UNIQUE (\"role_id\", \"Guid\")"));
        assertTrue(members.upsertSql().contains("ON CONFLICT (\"role_id\", \"Guid\") DO UPDATE SET"));
    }

    @Test
    void dbConfigReadsPgVariablesAndDefaultsToTheCyberArkSchema() {
        Map<String, String> env = new HashMap<>();
        env.put("PG_HOST", "localhost");
        env.put("PG_DATABASE", "my_local_db");
        env.put("PG_USERNAME", "postgres");
        env.put("PG_PASSWORD", "secret-pw");

        DbConfig config = DbConfig.fromEnvironment(env);

        assertEquals("jdbc:postgresql://localhost:5432/my_local_db", config.jdbcUrl());
        assertEquals("cyberark", config.schema());
        assertFalse(config.toString().contains("secret-pw"));

        env.remove("PG_PASSWORD");
        ConfigException e = assertThrows(ConfigException.class, () -> DbConfig.fromEnvironment(env));
        assertTrue(e.getMessage().contains("PG_PASSWORD"));
    }
}
