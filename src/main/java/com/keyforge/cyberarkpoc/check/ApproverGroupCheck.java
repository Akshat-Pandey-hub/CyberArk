package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Use case 1: every approver role matching the name pattern must have at least {@code minApprovers}
 * valid approvers.
 *
 * <p>Flow (as in the client mail, plus GetRoleMembers because GetRole does not return members):
 * Redrock role search, then for each role GetRole and GetRoleMembers, then a user lookup per member.
 *
 * <p>A member counts as a valid approver only when it is a user, the user exists, and its
 * {@code StatusEnum} is {@code Active}. The localized {@code Status} is never used for the decision,
 * not even as a fallback; it only appears in the exclusion detail. Nested roles are expanded through
 * GetRoleMembers.
 * Groups cannot be expanded with a known API, so they are reported as unresolved and never counted.
 * SailPoint identity status is deliberately not consulted in this phase.
 *
 * <p>Any API failure propagates as an exception, so a failed run never looks like a passing one.
 */
public final class ApproverGroupCheck {

    public static final String DEFAULT_PATTERN = "APP-CYA-ISPSS-SCA-AWS-%-BUApprovers";
    public static final int DEFAULT_MIN_APPROVERS = 3;
    /** The documented {@code StatusEnum} value of a usable account (the only eligible value for now). */
    public static final String ACTIVE_STATUS = "Active";

    private final CyberArkClient client;
    private final String rolePattern;
    private final int minApprovers;

    public ApproverGroupCheck(CyberArkClient client) {
        this(client, DEFAULT_PATTERN, DEFAULT_MIN_APPROVERS);
    }

    public ApproverGroupCheck(CyberArkClient client, String rolePattern, int minApprovers) {
        if (minApprovers < 1) {
            throw new IllegalArgumentException("minApprovers must be at least 1");
        }
        this.client = client;
        this.rolePattern = rolePattern;
        this.minApprovers = minApprovers;
    }

    public ApproverGroupReport run() {
        List<RoleResult> results = new ArrayList<>();
        for (Role role : client.findRolesByNamePattern(rolePattern)) {
            results.add(checkRole(role));
        }
        return new ApproverGroupReport(rolePattern, minApprovers, results);
    }

    private RoleResult checkRole(Role role) {
        RoleDetails details = client.getRole(role.id());
        Map<String, CyberArkUser> valid = new LinkedHashMap<>();
        List<ExcludedMember> excluded = new ArrayList<>();
        List<RoleMember> unresolvedGroups = new ArrayList<>();
        Set<String> visitedRoles = new HashSet<>();
        visitedRoles.add(role.id());
        collect(role.id(), role.name(), valid, excluded, unresolvedGroups, visitedRoles, new HashSet<>());
        Outcome outcome = valid.size() >= minApprovers ? Outcome.SUFFICIENT : Outcome.INSUFFICIENT;
        return new RoleResult(role, details, List.copyOf(valid.values()), excluded, unresolvedGroups, outcome);
    }

    private void collect(String roleId, String roleName, Map<String, CyberArkUser> valid,
                         List<ExcludedMember> excluded, List<RoleMember> unresolvedGroups,
                         Set<String> visitedRoles, Set<String> seenUsers) {
        for (RoleMember member : client.getRoleMembers(roleId)) {
            switch (member.type()) {
                case USER -> {
                    if (seenUsers.add(member.id())) {
                        checkUser(member, roleName, valid, excluded);
                    }
                }
                case ROLE -> {
                    if (visitedRoles.add(member.id())) {
                        collect(member.id(), member.name(), valid, excluded, unresolvedGroups, visitedRoles, seenUsers);
                    }
                }
                case GROUP -> unresolvedGroups.add(member);
                case UNKNOWN -> excluded.add(new ExcludedMember(member, roleName, Reason.UNKNOWN_MEMBER_TYPE,
                        "type '" + member.rawType() + "'"));
            }
        }
    }

    private void checkUser(RoleMember member, String viaRole, Map<String, CyberArkUser> valid,
                           List<ExcludedMember> excluded) {
        Optional<CyberArkUser> found = client.findUserById(member.id());
        if (found.isEmpty()) {
            excluded.add(new ExcludedMember(member, viaRole, Reason.USER_NOT_FOUND, "no User row"));
            return;
        }
        CyberArkUser user = found.get();
        String shown = " (Status=" + user.status() + ")";
        if (user.statusEnum() == null || user.statusEnum().isBlank()) {
            excluded.add(new ExcludedMember(member, viaRole, Reason.STATUS_UNKNOWN, "no StatusEnum value" + shown));
        } else if (!user.statusEnum().trim().toLowerCase(Locale.ROOT).equals(ACTIVE_STATUS.toLowerCase(Locale.ROOT))) {
            excluded.add(new ExcludedMember(member, viaRole, Reason.ACCOUNT_NOT_ACTIVE,
                    "StatusEnum=" + user.statusEnum() + shown));
        } else {
            valid.put(user.id(), user);
        }
    }

    public enum Outcome { SUFFICIENT, INSUFFICIENT }

    public enum Reason {
        USER_NOT_FOUND,
        ACCOUNT_NOT_ACTIVE,
        /** StatusEnum was absent; the user is not counted rather than guessed valid. */
        STATUS_UNKNOWN,
        UNKNOWN_MEMBER_TYPE
    }

    /** A member that was not counted. {@code viaRole} is the role (top-level or nested) it came from. */
    public record ExcludedMember(RoleMember member, String viaRole, Reason reason, String detail) {
    }

    public record RoleResult(
            Role role,
            RoleDetails details,
            List<CyberArkUser> validApprovers,
            List<ExcludedMember> excluded,
            List<RoleMember> unresolvedGroups,
            Outcome outcome) {
    }

    public record ApproverGroupReport(String rolePattern, int minApprovers, List<RoleResult> roles) {

        public boolean noRolesFound() {
            return roles.isEmpty();
        }

        public List<RoleResult> insufficient() {
            return roles.stream().filter(r -> r.outcome() == Outcome.INSUFFICIENT).toList();
        }
    }
}
