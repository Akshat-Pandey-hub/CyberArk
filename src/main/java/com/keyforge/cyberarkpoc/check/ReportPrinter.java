package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ApproverGroupReport;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.MemberResult;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.Outcome;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.RoleResult;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.PolicyHealthReport;
import com.keyforge.cyberarkpoc.model.Policy;

import java.io.PrintStream;

/** Plain-text console report. Nothing is sent anywhere; notifications are out of scope for this phase. */
public final class ReportPrinter {

    private ReportPrinter() {
    }

    public static void print(ApproverGroupReport report, PrintStream out) {
        out.println("USE CASE 1 - approver roles (pattern " + report.rolePattern()
                + ", minimum " + report.minApprovers() + " direct members and verified active users)");
        out.println("  Role search: " + report.search().roles().size() + " role(s), " + report.search().pages()
                + " page(s), " + (report.search().complete() ? "complete" : "INCOMPLETE"));
        report.search().notes().forEach(n -> out.println("    note: " + n));
        out.println("  " + ApproverGroupCheck.VISIBILITY_NOTE);
        if (report.noRolesFound()) {
            out.println("  No visible role matched the pattern.");
            return;
        }
        for (RoleResult role : report.roles()) {
            out.println("  [" + role.outcome() + "] " + role.role().name() + " (id " + role.role().id() + "): "
                    + role.directMembers() + " direct " + role.directMembersByType() + ", "
                    + role.activeUsers() + " verified active");
            role.reasons().forEach(r -> out.println("      reason    " + r));
            role.notes().forEach(n -> out.println("      note      " + n));
            for (MemberResult m : role.members()) {
                out.println("      " + (m.countsAsActive() ? "active    " : "member    ") + m.name() + " - "
                        + m.outcome() + (m.viaRoleName() == null ? "" : " (via " + m.viaRoleName() + ")")
                        + ": " + m.detail());
            }
        }
        out.println("  PASS " + report.count(Outcome.PASS) + ", FAIL " + report.count(Outcome.FAIL)
                + ", CANNOT_VERIFY " + report.count(Outcome.CANNOT_VERIFY) + ", CHECK_FAILED "
                + report.count(Outcome.CHECK_FAILED) + " of " + report.roles().size() + " role(s)");
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
