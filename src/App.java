
//****************************************************************************//
/*
 * Project: Cyber Knight Sec - Audit
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

        // Stop the program if the domain entry is invalid
        if (!isValidDomain(domainInput)) {
            System.out.println();
            System.out.println("Invalid domain entry.");
            System.out.println(
                    "Enter only the domain name, such as example.org."
            );

            scanner.close();
            return;
        }

        // Create an object to store the domain and audit results
        ClientDomain prospect =
                new ClientDomain(domainInput);

        System.out.println();
        System.out.println(
                "Performing live email security scan..."
        );

        // Perform the DNS audit
        auditService.runAudit(prospect);

        // Display the completed audit report
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
                "----------------------------------------------"
        );
        System.out.println(
                "STATUS: " + prospect.getAssessment()
        );

        // Recommend an SPF record when one was not found
        if (prospect.isSpfMissing()) {
            System.out.println(
                    "Recommendation: Add or review the SPF record."
            );
        }

        // Recommend a DMARC policy when one was not found
        if (prospect.isDmarcMissing()) {
            System.out.println(
                    "Recommendation: Add or review the DMARC policy."
            );
        }

        // Recommend a deeper policy review when both records exist
        if (!prospect.isSpfMissing()
                && !prospect.isDmarcMissing()) {

            System.out.println(
                    "Recommendation: Review SPF and DMARC policy strength."
            );
        }

        System.out.println(
                "=============================================="
        );
    }
}
