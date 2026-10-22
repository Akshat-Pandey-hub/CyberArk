package com.keyforge.cyberarkpoc.store;

import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.extract.PvwaExtraction;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SQL and naming rules of the store, without a database. */
class StoreSqlTest {

    private static RawRecordRepository safes() {
        return new RawRecordRepository("cyberark", "pvwa_safe", PvwaExtraction.SAFE_COLUMNS, "safeUrlId");
    }

    @Test
    void safeTableHasOneColumnPerDocumentedFieldUnderTheSameName() {
        assertEquals("CREATE TABLE IF NOT EXISTS cyberark.pvwa_safe (\n"
                + "    record_uuid uuid PRIMARY KEY,\n"
                + "    \"safeUrlId\" text NOT NULL UNIQUE,\n"
                + "    \"safeName\" text,\n"
                + "    \"safeNumber\" bigint,\n"
                + "    \"description\" text,\n"
                + "    \"location\" text,\n"
                + "    \"creator\" jsonb,\n"
                + "    \"accounts\" jsonb,\n"
                + "    \"olacEnabled\" boolean,\n"
                + "    \"managingCPM\" text,\n"
                + "    \"numberOfVersionsRetention\" bigint,\n"
                + "    \"numberOfDaysRetention\" bigint,\n"
                + "    \"autoPurgeEnabled\" boolean,\n"
                + "    \"creationTime\" bigint,\n"
                + "    \"lastModificationTime\" bigint,\n"
                + "    \"isExpiredMember\" boolean,\n"
                + "    extracted_at timestamp with time zone NOT NULL DEFAULT now()\n"
                + ")", safes().createTableSql());
    }

    @Test
    void accountTableHasNoSecretColumn() {
        String ddl = new RawRecordRepository("cyberark", "pvwa_account", PvwaExtraction.ACCOUNT_COLUMNS, "id")
                .createTableSql();

        assertTrue(ddl.contains("\"id\" text NOT NULL UNIQUE"));
        assertTrue(ddl.contains("\"secretManagement\" jsonb"));
        assertFalse(ddl.toLowerCase().contains("\"secret\""), ddl);
    }

    @Test
    void upsertUpdatesByTheCyberArkIdAndKeepsTheUuid() {
        String sql = safes().upsertSql();

        assertTrue(sql.contains("ON CONFLICT (\"safeUrlId\") DO UPDATE SET \"safeName\" = EXCLUDED.\"safeName\""));
        assertFalse(sql.contains("record_uuid = EXCLUDED"), "an existing row keeps its uuid");
        assertTrue(sql.contains("\"creator\""));
        assertTrue(sql.endsWith("RETURNING (xmax = 0)"));
    }

    @Test
    void safeMemberTableUsesTheSafeAndMemberTogetherAsItsKey() {
        RawRecordRepository members = new RawRecordRepository("cyberark", "pvwa_safe_member",
                PvwaExtraction.SAFE_MEMBER_COLUMNS, List.of("safeUrlId", "memberId"));
        String ddl = members.createTableSql();

        assertTrue(ddl.contains("\"safeUrlId\" text NOT NULL,"), ddl);
        assertTrue(ddl.contains("\"memberId\" bigint NOT NULL,"), ddl);
        assertFalse(ddl.contains("NOT NULL UNIQUE"), "neither field is unique on its own");
        assertTrue(ddl.contains("UNIQUE (\"safeUrlId\", \"memberId\")"), ddl);
        assertTrue(ddl.contains("\"permissions\" jsonb"));
        assertTrue(members.upsertSql().contains("ON CONFLICT (\"safeUrlId\", \"memberId\") DO UPDATE SET"));
        assertFalse(members.upsertSql().contains("\"memberId\" = EXCLUDED"), "key fields are not rewritten");
    }

    @Test
    void namesAreValidated() {
        assertThrows(ConfigException.class,
                () -> new RawRecordRepository("bad-name", "pvwa_safe", PvwaExtraction.SAFE_COLUMNS, "safeUrlId"));
        assertThrows(IllegalArgumentException.class,
                () -> new RawRecordRepository("s", "Pvwa Safe", PvwaExtraction.SAFE_COLUMNS, "safeUrlId"));
        assertThrows(IllegalArgumentException.class,
                () -> new RawRecordRepository("s", "pvwa_safe", PvwaExtraction.SAFE_COLUMNS, "nope"));
        assertThrows(IllegalArgumentException.class, () -> Column.text("x\"; drop"));
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
