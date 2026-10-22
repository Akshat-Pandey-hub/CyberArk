package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.client.CyberArkClient.RoleSearch;
import com.keyforge.cyberarkpoc.client.IdentityResponses.MemberList;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Use case 1: every approver role matching the name pattern needs at least {@code minApprovers} direct members and at
 * least {@code minApprovers} verified active users. Contract: docs/API_CONTRACT.md (rules in §8).
 *
 * <p>Flow: a paged Redrock role search, then per role GetRole (the call the client mail names), the role's members,
 * a User lookup per user member, and the expansion of nested roles.
 *
 * <ul>
 *   <li><b>Direct members</b> are every distinct member the members API lists for the role, of any type, counted by
 *       type. A group or a nested role counts as one direct member, never as an approver.</li>
 *   <li><b>Verified active users</b> are distinct users, directly or through an expanded nested role, whose User row
 *       has {@code StatusEnum} {@code Active} (any letter case). The localized {@code Status} is never used.</li>
 *   <li>A nested role is expanded only when the Role table shows it as a {@code PrincipalList} role (the documented
 *       explicit list); {@code Everybody} / {@code Script} roles and roles the service user cannot see are not.
 *       Every role is expanded at most once, so a cycle ends.</li>
 *   <li>Groups cannot be expanded (no documented API), so they are reported and never counted.</li>
 * </ul>
 *
 * <p>Outcome per role: {@code PASS} when both thresholds are met; {@code FAIL} when a threshold is definitely missed;
 * {@code CANNOT_VERIFY} when unresolved members (groups, roles not expanded, users without a User row or status, an
 * incomplete member list, a non-PrincipalList role) could still change the result; {@code CHECK_FAILED} when an API
 * call for the role failed or answered something malformed. A failure of the role search itself is thrown.
 */
public final class ApproverGroupCheck {

    public static final String DEFAULT_PATTERN = "APP-CYA-ISPSS-SCA-AWS-%-BUApprovers";
    public static final int DEFAULT_MIN_APPROVERS = 3;
    public static final int DEFAULT_PAGE_SIZE = 1000;
    public static final int DEFAULT_MAX_PAGES = 1000;
    /** The documented {@code StatusEnum} value of a usable account (the only eligible value). */
    public static final String ACTIVE_STATUS = "Active";

    /** Always reported: the documented Redrock visibility rule, so an empty or short result is never taken as proof. */
    public static final String VISIBILITY_NOTE = "Redrock queries only return data that the service user has access "
            + "to (official 'Use queries' page). Roles, members or users the service user cannot see are left out "
            + "without an error, so a missing role is not proof that it does not exist; that depends on the service "
            + "user's rights, which the client must confirm";

    public enum Outcome { PASS, FAIL, CANNOT_VERIFY, CHECK_FAILED }

    /** What happened to one member. */
    public enum MemberOutcome {
        ACTIVE_USER,
        USER_NOT_ACTIVE,
        USER_STATUS_MISSING,
        USER_NOT_FOUND,
        USER_ALREADY_COUNTED,
        GROUP_NOT_EXPANDED,
        NESTED_ROLE_EXPANDED,
        NESTED_ROLE_NOT_EXPANDED,
        NESTED_ROLE_NOT_VISIBLE,
        ROLE_ALREADY_EXPANDED,
        UNKNOWN_MEMBER_TYPE,
        DUPLICATE
    }

    /**
     * One member line of a role's result.
     *
     * @param viaRoleId   the nested role it was reached through, or {@code null} for a direct member
     * @param countsAsActive whether it is one of the role's verified active users
     */
    public record MemberResult(String id, String name, String type, String viaRoleId, String viaRoleName,
                               MemberOutcome outcome, boolean countsAsActive, String detail) {
    }

    /** The member rows one members-API call returned for {@code roleId}, kept for storage. */
    public record MemberRows(String roleId, List<RoleMember> members) {
    }

    /**
     * The result for one role.
     *
     * @param totalThresholdMet  {@code true} / {@code false} when established, {@code null} when it could not be
     * @param activeThresholdMet same for the verified active users
     */
    public record RoleResult(
            Role role,
            RoleDetails details,
            Outcome outcome,
            List<String> reasons,
            int directMembers,
            Map<String, Integer> directMembersByType,
            int activeUsers,
            Boolean totalThresholdMet,
            Boolean activeThresholdMet,
            List<MemberResult> members,
            List<String> notes,
            String error,
            List<MemberRows> memberRows,
            List<Role> nestedRoles,
            List<CyberArkUser> users) {
    }

    public record ApproverGroupReport(String rolePattern, int minApprovers, RoleSearch search, List<RoleResult> roles) {

        public boolean noRolesFound() {
            return roles.isEmpty();
        }

        public long count(Outcome outcome) {
            return roles.stream().filter(r -> r.outcome() == outcome).count();
        }
    }

    private final CyberArkClient client;
    private final String rolePattern;
    private final int minApprovers;
    private final int pageSize;
    private final int maxPages;

    public ApproverGroupCheck(CyberArkClient client) {
        this(client, DEFAULT_PATTERN, DEFAULT_MIN_APPROVERS);
    }

    public ApproverGroupCheck(CyberArkClient client, String rolePattern, int minApprovers) {
        this(client, rolePattern, minApprovers, DEFAULT_PAGE_SIZE, DEFAULT_MAX_PAGES);
    }

    public ApproverGroupCheck(CyberArkClient client, String rolePattern, int minApprovers, int pageSize, int maxPages) {
        if (minApprovers < 1) {
            throw new IllegalArgumentException("minApprovers must be at least 1");
        }
        this.client = client;
        this.rolePattern = rolePattern;
        this.minApprovers = minApprovers;
        this.pageSize = pageSize;
        this.maxPages = maxPages;
    }

    /** Runs the check. A failed role search throws {@link CyberArkApiException}; a failed role is CHECK_FAILED. */
    public ApproverGroupReport run() {
        RoleSearch search = client.findRolesByNamePattern(rolePattern, pageSize, maxPages);
        List<RoleResult> results = new ArrayList<>();
        for (Role role : search.roles()) {
            results.add(checkRole(role));
        }
        return new ApproverGroupReport(rolePattern, minApprovers, search, results);
    }

    private RoleResult checkRole(Role role) {
        Evaluation ev = new Evaluation(role);
        try {
            ev.details = client.getRole(role.id());
            MemberList direct = client.getRoleMembers(role.id());
            ev.memberRows.add(new MemberRows(role.id(), direct.members()));
            if (!role.hasExplicitMembers()) {
                ev.directListAuthoritative = false;
                ev.unbounded("the role's RoleType is " + quoted(role.roleType()) + ", not PrincipalList, so its member "
                        + "list may not be its real membership");
            }
            String incomplete = incompleteness(direct);
            if (incomplete != null) {
                ev.directListAuthoritative = false;
                ev.unbounded("the role's member list may be incomplete: " + incomplete);
            }
            Set<String> directIds = new LinkedHashSet<>();
            for (RoleMember member : direct.members()) {
                if (!directIds.add(member.id())) {
                    ev.member(member, null, MemberOutcome.DUPLICATE, false, "listed more than once; counted once");
                    continue;
                }
                ev.directByType.merge(typeLabel(member), 1, Integer::sum);
                process(member, null, ev);
            }
            ev.directMembers = directIds.size();
            return ev.result(minApprovers);
        } catch (CyberArkApiException e) {
            ev.error = client.sanitize(e.getMessage());
            return ev.failed(minApprovers);
        }
    }

    private void process(RoleMember member, Role via, Evaluation ev) {
        switch (member.type()) {
            case USER -> checkUser(member, via, ev);
            case GROUP -> {
                ev.unbounded("group " + member.name() + " cannot be expanded (no documented API)");
                ev.member(member, via, MemberOutcome.GROUP_NOT_EXPANDED, false,
                        "groups are not expanded or counted; its members are unknown");
            }
            case ROLE -> expandRole(member, via, ev);
            case UNKNOWN -> {
                ev.bounded++;
                ev.member(member, via, MemberOutcome.UNKNOWN_MEMBER_TYPE, false,
                        "type " + quoted(member.rawType()) + " is not User, Group or Role");
            }
        }
    }

    private void checkUser(RoleMember member, Role via, Evaluation ev) {
        if (!ev.seenUsers.add(member.id())) {
            ev.member(member, via, MemberOutcome.USER_ALREADY_COUNTED, false,
                    "already evaluated through another path; not counted twice");
            return;
        }
        Optional<CyberArkUser> found = client.findUserById(member.id());
        if (found.isEmpty()) {
            ev.bounded++;
            ev.member(member, via, MemberOutcome.USER_NOT_FOUND, false,
                    "no User row (the User table lists users who have accessed the cloud service, so this is "
                            + "not proof the user is inactive)");
            return;
        }
        CyberArkUser user = found.get();
        ev.users.add(user);
        String shown = "StatusEnum=" + user.statusEnum() + " (Status=" + user.status() + ")";
        if (user.statusEnum() == null || user.statusEnum().isBlank()) {
            ev.bounded++;
            ev.member(member, via, MemberOutcome.USER_STATUS_MISSING, false, "no StatusEnum value; " + shown);
        } else if (user.statusEnum().trim().toLowerCase(Locale.ROOT).equals(ACTIVE_STATUS.toLowerCase(Locale.ROOT))) {
            ev.active.add(user.id());
            ev.member(member, via, MemberOutcome.ACTIVE_USER, true, shown);
        } else {
            ev.member(member, via, MemberOutcome.USER_NOT_ACTIVE, false, shown);
        }
    }

    private void expandRole(RoleMember member, Role via, Evaluation ev) {
        if (!ev.visitedRoles.add(member.id())) {
            ev.member(member, via, MemberOutcome.ROLE_ALREADY_EXPANDED, false, "already expanded; not repeated");
            return;
        }
        Optional<Role> nested = client.findRoleById(member.id());
        if (nested.isEmpty()) {
            ev.unbounded("nested role " + member.name() + " is not visible in the Role table");
            ev.member(member, via, MemberOutcome.NESTED_ROLE_NOT_VISIBLE, false,
                    "not visible in the Role table, so it was not expanded");
            return;
        }
        Role role = nested.get();
        ev.nestedRoles.add(role);
        if (!role.hasExplicitMembers()) {
            ev.unbounded("nested role " + member.name() + " has RoleType " + quoted(role.roleType()));
            ev.member(member, via, MemberOutcome.NESTED_ROLE_NOT_EXPANDED, false,
                    "RoleType " + quoted(role.roleType()) + " is not PrincipalList, so it was not expanded");
            return;
        }
        MemberList list = client.getRoleMembers(role.id());
        ev.memberRows.add(new MemberRows(role.id(), list.members()));
        String incomplete = incompleteness(list);
        if (incomplete != null) {
            ev.unbounded("the member list of nested role " + member.name() + " may be incomplete: " + incomplete);
        }
        ev.member(member, via, MemberOutcome.NESTED_ROLE_EXPANDED, false,
                list.members().size() + " member(s) listed; the role itself is not an approver");
        Set<String> ids = new HashSet<>();
        for (RoleMember child : list.members()) {
            if (!ids.add(child.id())) {
                ev.member(child, role, MemberOutcome.DUPLICATE, false, "listed more than once; counted once");
                continue;
            }
            process(child, role, ev);
        }
    }

    /** Why a member list may be incomplete, or {@code null} when nothing indicates it. */
    private static String incompleteness(MemberList list) {
        List<String> why = new ArrayList<>();
        if (list.reportedTotal() != null && list.reportedTotal() > list.members().size()) {
            why.add("FullCount " + list.reportedTotal() + " but " + list.members().size() + " listed");
        }
        if (list.softError()) {
            why.add("the response flagged IsSoftError (meaning undocumented)");
        }
        return why.isEmpty() ? null : String.join("; ", why);
    }

    private static String typeLabel(RoleMember member) {
        return switch (member.type()) {
            case USER -> "User";
            case GROUP -> "Group";
            case ROLE -> "Role";
            case UNKNOWN -> "Unknown";
        };
    }

    private static String quoted(String value) {
        return value == null ? "(none)" : "'" + value + "'";
    }

    /** Collects one role's evaluation, then decides the outcome. */
    private static final class Evaluation {
        final Role role;
        RoleDetails details;
        int directMembers;
        final Map<String, Integer> directByType = new LinkedHashMap<>();
        final Set<String> active = new LinkedHashSet<>();
        final Set<String> seenUsers = new HashSet<>();
        final Set<String> visitedRoles = new HashSet<>();
        final List<MemberResult> members = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
        final List<MemberRows> memberRows = new ArrayList<>();
        final List<Role> nestedRoles = new ArrayList<>();
        final List<CyberArkUser> users = new ArrayList<>();
        /** Members that could each add at most one active user (users without a User row or status, unknown types). */
        int bounded;
        /** Something could add any number of active users (a group, a role not expanded, an incomplete list). */
        boolean unbounded;
        /** False when the direct member list may not be the role's real membership. */
        boolean directListAuthoritative = true;
        String error;

        Evaluation(Role role) {
            this.role = role;
            visitedRoles.add(role.id());
            for (String type : List.of("User", "Group", "Role", "Unknown")) {
                directByType.put(type, 0);
            }
        }

        void unbounded(String why) {
            unbounded = true;
            notes.add(why);
        }

        void member(RoleMember m, Role via, MemberOutcome outcome, boolean countsAsActive, String detail) {
            members.add(new MemberResult(m.id(), m.name(), m.rawType(), via == null ? null : via.id(),
                    via == null ? null : via.name(), outcome, countsAsActive, detail));
        }

        RoleResult result(int min) {
            int activeUsers = active.size();
            boolean totalMet = directMembers >= min;
            boolean totalMissed = !totalMet && directListAuthoritative;
            boolean activeMet = activeUsers >= min;
            boolean activeMissed = !activeMet && !unbounded && activeUsers + bounded < min;
            List<String> reasons = new ArrayList<>();
            if (totalMet) {
                reasons.add(directMembers + " direct member(s), at least " + min);
            } else if (totalMissed) {
                reasons.add("only " + directMembers + " direct member(s), fewer than " + min);
            } else {
                reasons.add(directMembers + " direct member(s) listed, fewer than " + min
                        + ", but the member list may not be complete");
            }
            if (activeMet) {
                reasons.add(activeUsers + " verified active user(s), at least " + min);
            } else if (activeMissed) {
                reasons.add("only " + activeUsers + " verified active user(s), fewer than " + min
                        + (bounded > 0 ? ", even if the " + bounded + " unresolved user(s) were active" : ""));
            } else {
                reasons.add(activeUsers + " verified active user(s), fewer than " + min
                        + ", but unresolved members could add more");
            }
            Outcome outcome = totalMet && activeMet ? Outcome.PASS
                    : totalMissed || activeMissed ? Outcome.FAIL
                    : Outcome.CANNOT_VERIFY;
            return new RoleResult(role, details, outcome, reasons, directMembers, java.util.Collections.unmodifiableMap(new LinkedHashMap<>(directByType)),
                    activeUsers, totalMet ? Boolean.TRUE : totalMissed ? Boolean.FALSE : null,
                    activeMet ? Boolean.TRUE : activeMissed ? Boolean.FALSE : null, List.copyOf(members),
                    List.copyOf(notes), null, List.copyOf(memberRows), List.copyOf(nestedRoles), List.copyOf(users));
        }

        RoleResult failed(int min) {
            return new RoleResult(role, details, Outcome.CHECK_FAILED,
                    List.of("the check could not complete: " + error), directMembers, java.util.Collections.unmodifiableMap(new LinkedHashMap<>(directByType)),
                    active.size(), null, null, List.copyOf(members), List.copyOf(notes), error,
                    List.copyOf(memberRows), List.copyOf(nestedRoles), List.copyOf(users));
        }
    }
}
