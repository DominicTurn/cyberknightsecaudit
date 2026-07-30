//****************************************************************************//
/*
 * Project: Cyber Knight Sec - Scout
 * Author: Dominic Turner
 * File: App.java
 *
 * Accepts a domain from the user, runs the DNS audit, and
 * displays the SPF, DMARC, and assessment results.
 */
//****************************************************************************//

import java.util.Scanner;

public class App {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Create the service that performs DNS lookups
        DnsAuditService auditService = new DnsAuditService();

        System.out.println(
                "=============================================="
        );
        System.out.println(
                "       CYBER KNIGHT SEC - SCOUT v1.0"
        );
        System.out.println(
                "=============================================="
        );

        System.out.print(
                "Enter a domain to audit (e.g., example.org): "
        );

        // Clean the user's input before validating it
        String domainInput =
                scanner.nextLine().trim().toLowerCase();

        // Stop the program when the input is not a valid domain
        if (!isValidDomain(domainInput)) {
            System.out.println();
            System.out.println("Invalid domain entry.");
            System.out.println(
                    "Enter only the domain name, such as example.org."
            );

            scanner.close();
            return;
        }

        // Store the domain and its audit results
        ClientDomain prospect =
                new ClientDomain(domainInput);

        // DKIM has no fixed record location, so allow the analyst to
        // supply a known selector for a definitive check. The tool
        // will also probe a list of common provider selectors either way.
        System.out.print(
                "Enter a known DKIM selector, if any (press Enter to skip): "
        );

        String dkimSelectorInput = scanner.nextLine().trim();

        System.out.println();
        System.out.println(
                "Performing live email security scan..."
        );

        // Run the DNS audit
        auditService.runAudit(prospect, dkimSelectorInput);

        // Display the completed report
        printAuditReport(prospect);

        scanner.close();
    }

    private static boolean isValidDomain(String domain) {
        // Reject blank entries, URLs, spaces, and incomplete domains
        return !domain.isBlank()
                && domain.contains(".")
                && !domain.contains(" ")
                && !domain.contains("/")
                && !domain.startsWith("http://")
                && !domain.startsWith("https://");
    }

    private static void printAuditReport(
            ClientDomain prospect) {

        System.out.println();
        System.out.println(
                "================ AUDIT REPORT ================"
        );
        System.out.println(
                "Target Domain: " + prospect.getDomainName()
        );
        System.out.println(
                "SPF Record:    " + prospect.getSpfRecord()
        );
        System.out.println(
                "DMARC Record:  " + prospect.getDmarcRecord()
        );
        System.out.println(
                "DKIM Record:   " + prospect.getDkimRecord()
        );

        if (!prospect.getDkimRecord().equals("MISSING")) {
            System.out.println(
                    "DKIM Selector: " + prospect.getDkimSelector()
            );
        }

        System.out.println(
                "----------------------------------------------"
        );
        System.out.println(
                "STATUS: " + prospect.getAssessment()
        );

        // Print recommendations for each missing record
        if (prospect.getSpfRecord().equals("MISSING")) {
            System.out.println(
                    "Recommendation: Add or review the SPF record."
            );
        }

        if (prospect.getDmarcRecord().equals("MISSING")) {
            System.out.println(
                    "Recommendation: Add or review the DMARC policy."
            );
        }

        if (prospect.getDkimRecord().equals("MISSING")) {
            System.out.println(
                    "Recommendation: Add DKIM signing, or re-run with the"
                            + " client's known selector to confirm."
            );
        }

        if (!prospect.getSpfRecord().equals("MISSING")
                && !prospect.getDmarcRecord().equals("MISSING")
                && !prospect.getDkimRecord().equals("MISSING")) {

            System.out.println(
                    "Recommendation: Review SPF, DKIM, and DMARC policy"
                            + " strength."
            );
        }

        System.out.println(
                "=============================================="
        );
    }
}
