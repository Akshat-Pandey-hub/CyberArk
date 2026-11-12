package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parsing against bodies published by CyberArk (documentation examples, OpenAPI example values and
 * public SwaggerHub mock responses). Sources and editorial changes: src/test/resources/official/FIXTURES.md.
 *
 * <p>These prove the parsers accept CyberArk's published shapes. They do not prove that a real
 * tenant returns the same shapes.
 */
class OfficialExamplesContractTest {

    private static String fixture(String name) {
        try (InputStream in = OfficialExamplesContractTest.class.getResourceAsStream("/official/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static JsonNode json(String name) {
        return Json.parse(name, 200, fixture(name));
    }

    private static CyberArkConfig stubConfig(String rootUrl) {
        return new CyberArkConfig(URI.create(rootUrl + "/api"),
                URI.create(rootUrl + "/oauth2/platformtoken"), "client", "secret", Duration.ofSeconds(5));
    }

    // ---- Redrock envelope -----------------------------------------------------------------

    @Test
    void redrockSuccessEnvelopeFromOfficialUserQuery() {
        List<CyberArkUser> users = IdentityResponses.users("test", json("redrock-user-query.official-derived.json"));

        assertEquals(4, users.size(), "every published row is read; Entities and Columns are ignored");
        assertEquals("e7ed3e73-d115-44f3-9553-4bcc1a4ecc05", users.get(0).id());
        assertEquals("auser1@qa.com", users.get(0).username());
        assertNull(users.get(0).statusEnum(), "this example selects only ID and Username");
    }

    @Test
    void redrockFailureFromOfficialExampleIsAnApiFailure() {
        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> IdentityResponses.rows("test", json("redrock-failure.official-derived.json")));

        assertEquals(CyberArkApiException.Kind.API_FAILURE, e.kind());
        assertTrue(e.getMessage().contains("no such table: Users"), e.getMessage());
    }

    // ---- Role table and members -----------------------------------------------------------

    @Test
    void roleRowFromOfficialRoleTable() {
        List<Role> roles = IdentityResponses.roles("test", json("redrock-role-table.official-derived.json"));

        assertEquals(1, roles.size());
        assertEquals("ccbf30c...", roles.get(0).id());
        assertEquals("admin portal", roles.get(0).name());
        assertNull(roles.get(0).description());
    }

    @Test
    void flatMembersFromOfficialSaasManageExample() {
        List<RoleMember> members = IdentityResponses.roleMembers("test",
                json("saasmanage-getrolemembers-flat.official-derived.json")).members();

        assertEquals(1, members.size());
        assertEquals("cee2bfa4...", members.get(0).id());
        assertEquals("test@mytenant.idaptive.com", members.get(0).name());
        assertEquals(RoleMember.Type.USER, members.get(0).type());
        assertEquals("User", members.get(0).rawType(), "documented wire casing");
    }

    @Test
    void nestedMembersSchemaExampleIsReadInItsDocumentedShape() {
        IdentityResponses.MemberList list = IdentityResponses.roleMembers("test",
                json("roles-getrolemembers-nested.official-schema-example.json"));

        assertEquals("nested", list.shape());
        assertEquals(1, list.members().size(), "one member in the example's Row array");
        assertEquals("string", list.members().get(0).id(), "the schema example's placeholder Guid");
        assertEquals(0, list.reportedTotal(), "the example's FullCount placeholder");
        assertTrue(list.softError(), "the example sets IsSoftError true; the check treats that as incomplete");
    }

    @Test
    void getRoleFromOfficialSchemaExample() {
        RoleDetails details = IdentityResponses.roleDetails("test", json("roles-getrole.official-schema-example.json"));

        assertEquals("string", details.id(), "read from Uuid");
        assertEquals("string", details.name());
        assertEquals("string", details.roleType());
        assertEquals(List.of("string"), details.principals());
    }

    // ---- User status (A2) -----------------------------------------------------------------

    @Test
    void statusEnumAndLocalizedStatusAreReadSeparately() {
        List<CyberArkUser> users = IdentityResponses.users("test",
                json("redrock-user-column-data.official-derived.json"));

        assertEquals("Active", users.get(0).statusEnum());
        assertEquals("Active", users.get(0).status());
        assertEquals("Created", users.get(1).statusEnum());
        assertEquals("Not Invited", users.get(1).status(), "the localized text differs from the enum");
    }

    @Test
    void invitedStatusEnumFromOfficialUserDictionary() {
        List<CyberArkUser> users = IdentityResponses.users("test",
                json("redrock-user-dictionary.official-derived.json"));

        assertEquals(List.of("Invited", "Active"), users.stream().map(CyberArkUser::statusEnum).toList());
    }

    // ---- Policies (Use Case 2) --------------------------------------------------------------

    private static PolicyClient stubPolicyClient(String rootUrl) {
        return new PolicyClient(new PolicyConfig(PolicyConfig.Api.UAP, URI.create(rootUrl + "/api"),
                URI.create(rootUrl + "/oauth2/token/app"), "client", "secret", 50, 10, Duration.ofSeconds(5)));
    }

    @Test
    void publicMockPolicyIsReadWithItsDocumentedStatus() {
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/oauth2/token/app", 200, fixture("sca-token.official-schema-example.json"))
                .reply("/api/policies", 200, fixture("uap-policies.public-mock.json"))) {
            PolicyClient.Listing listing = stubPolicyClient(stub.rootUrl()).listPolicies();
            PolicyHealthCheck.PolicyResult r = PolicyHealthCheck.evaluate(PolicyConfig.Api.UAP,
                    listing.policies().get(0));

            assertEquals("5af2ccfe-98dd-42ad-aa5d-21ffdee1c2ed", r.policyId());
            assertEquals("My-Policy-All_DBs", r.name());
            assertEquals("Active", r.status());
            assertEquals("200", r.statusCode());
            assertEquals("All good", r.statusDescription());
            assertEquals("DB", r.targetCategory());
            assertEquals("FQDN/IP", r.locationType());
            assertEquals(PolicyHealthCheck.Outcome.NO_FINDING, r.outcome());
            // The public mock's nextToken "DS1_10;DS2_20" is repeated by the stub, and its total 42 does not match.
            assertFalse(listing.complete());
            assertEquals(42, listing.reportedTotal());
        }
    }

    @Test
    void schemaExampleWithAnEmptyPolicyObjectCannotBeVerified() {
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/oauth2/token/app", 200, fixture("sca-token.official-schema-example.json"))
                .reply("/api/policies", 200, fixture("uap-policies-200.official-schema-example.json"))) {
            PolicyClient.Listing listing = stubPolicyClient(stub.rootUrl()).listPolicies();

            assertEquals(PolicyHealthCheck.Outcome.CANNOT_VERIFY,
                    PolicyHealthCheck.evaluate(PolicyConfig.Api.UAP, listing.policies().get(0)).outcome());
            assertFalse(listing.complete(), "total 0 but one policy received");
        }
    }

    // ---- Over HTTP: UAP error body and the custom OAuth2 token --------------------------------

    @Test
    void uapErrorBodyFromOfficialExampleIsAnHttpStatusFailure() {
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/oauth2/token/app", 200, fixture("sca-token.official-schema-example.json"))
                .reply("/api/policies", 400, fixture("uap-error.official-schema-example.json"))) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class,
                    stubPolicyClient(stub.rootUrl())::listPolicies);

            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(400, e.httpStatus());
            assertTrue(e.getMessage().contains("UAP9999"), e.getMessage());
        }
    }

    @Test
    void customTokenFromOfficialExampleIsRequestedWithBasicAuthAndUsedAsBearer() {
        // The policies body is fabricated (empty, complete); only the token body is official.
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/oauth2/token/app", 200, fixture("sca-token.official-schema-example.json"))
                .reply("/api/policies", 200, "{\"results\": [], \"nextToken\": \"\", \"total\": 0}")) {
            PolicyClient.Listing listing = stubPolicyClient(stub.rootUrl()).listPolicies();

            assertTrue(listing.policies().isEmpty());
            assertTrue(listing.complete());
            String basic = java.util.Base64.getEncoder().encodeToString("client:secret".getBytes(StandardCharsets.UTF_8));
            assertEquals(List.of("Basic " + basic, "Bearer ***ACCESS TOKEN HERE***"), stub.authorizationHeaders());
        }
    }
}
