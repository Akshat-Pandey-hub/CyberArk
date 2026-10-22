package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ApproverGroupReport;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ExcludedMember;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.RoleResult;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.PolicyHealthReport;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Policy;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.io.PrintStream;

/** Plain-text console report. Nothing is sent anywhere; notifications are out of scope for this phase. */
public final class ReportPrinter {

    private ReportPrinter() {
    }

    public static void print(ApproverGroupReport report, PrintStream out) {
        out.println("USE CASE 1 - approver roles (pattern " + report.rolePattern()
                + ", minimum " + report.minApprovers() + " valid approvers)");
        if (report.noRolesFound()) {
            out.println("  No roles matched the pattern.");
            return;
        }
        for (RoleResult role : report.roles()) {
            out.println("  [" + role.outcome() + "] " + role.role().name() + " (id " + role.role().id() + "): "
                    + role.validApprovers().size() + " valid (GetRole lists " + role.details().principals().size()
                    + " principals)");
            for (CyberArkUser user : role.validApprovers()) {
                out.println("      valid     " + user.username());
            }
            for (ExcludedMember member : role.excluded()) {
                out.println("      excluded  " + member.member().name() + " - " + member.reason()
                        + " (" + member.detail() + ", via " + member.viaRole() + ")");
            }
            for (RoleMember group : role.unresolvedGroups()) {
                out.println("      group     " + group.name() + " - not expanded, not counted");
            }
        }
        out.println("  Insufficient roles: " + report.insufficient().size() + " of " + report.roles().size());
    }

    public static void print(PolicyHealthReport report, PrintStream out) {
        out.println("USE CASE 2 - access policies in Error or Warning");
        if (report.noPolicies()) {
            out.println("  The API returned no policies.");
            return;
        }
        for (Policy policy : report.flagged()) {
            out.println("  [" + policy.status() + "] " + policy.name() + " (id " + policy.policyId() + ", "
                    + policy.targetCategory() + "/" + policy.locationType() + "): "
                    + policy.statusCode() + " - " + policy.statusDescription());
        }
        for (Policy policy : report.unrecognisedStatus()) {
            out.println("  [UNRECOGNISED STATUS '" + policy.status() + "'] " + policy.name()
                    + " (id " + policy.policyId() + ")");
        }
        out.println("  Flagged: " + report.flagged().size() + " of " + report.totalPolicies() + " policies");
    }
}
