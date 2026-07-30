//****************************************************************************//
/*
 * Project: Cyber Knight Sec - Scout
 * Author: Dominic Turner
 * File: DnsAuditService.java
 *
 * Performs DNS lookups for SPF and DMARC records and stores
 * the results in a ClientDomain object.
 */
//****************************************************************************//

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.List;

public class DnsAuditService {

    // Selectors commonly used by mainstream email/marketing providers.
    // DKIM has no fixed record location, so we probe these as a best
    // effort in addition to any selector the analyst supplies directly.
    private static final String[] COMMON_DKIM_SELECTORS = {
            "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
            "dkim", "default", "mail", "smtp", "smtpapi",
            "sendgrid", "mailgun", "mailjet", "mandrill", "mlsend",
            "zoho", "pm", "cm", "everlytickey1", "everlytickey2"
    };

    public void runAudit(ClientDomain client) {
        runAudit(client, null);
    }

    public void runAudit(ClientDomain client, String dkimSelector) {
        InitialDirContext context = null;

        try {
            // Create the DNS connection
            context = new InitialDirContext();

            // Run the SPF, DMARC, and DKIM checks
            findSpfRecord(context, client);
            findDmarcRecord(context, client);
            findDkimRecord(context, client, dkimSelector);

            // Assign an assessment based on the records found
            setAssessment(client);

        } catch (NamingException e) {
            client.setAssessment("DNS LOOKUP ERROR");

            System.out.println(
                    "Unable to start the DNS lookup for: "
                            + client.getDomainName()
            );
        } finally {
            // Close the DNS connection after the audit
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                    System.out.println(
                            "Unable to close the DNS connection."
                    );
                }
            }
        }
    }

    private void findSpfRecord(
            InitialDirContext context,
            ClientDomain client) {

        try {
            // Request all TXT records from the main domain
            Attributes attributes = context.getAttributes(
                    "dns:/" + client.getDomainName(),
                    new String[]{"TXT"}
            );

            Attribute txtRecords = attributes.get("TXT");

            if (txtRecords != null) {
                // Search the TXT records for an SPF entry
                for (int i = 0; i < txtRecords.size(); i++) {
                    String record = txtRecords.get(i).toString();

                    if (record.toLowerCase().contains("v=spf1")) {
                        client.setSpfRecord(record);
                        break;
                    }
                }
            }

        } catch (NamingException e) {
            System.out.println(
                    "SPF lookup failed for: "
                            + client.getDomainName()
            );
        }
    }

    private void findDmarcRecord(
            InitialDirContext context,
            ClientDomain client) {

        try {
            // DMARC records are stored under the _dmarc subdomain
            Attributes attributes = context.getAttributes(
                    "dns:/_dmarc." + client.getDomainName(),
                    new String[]{"TXT"}
            );

            Attribute txtRecords = attributes.get("TXT");

            if (txtRecords != null) {
                // Search the TXT records for a DMARC entry
                for (int i = 0; i < txtRecords.size(); i++) {
                    String record = txtRecords.get(i).toString();

                    if (record.toLowerCase().contains("v=dmarc1")) {
                        client.setDmarcRecord(record);
                        client.setDmarcPolicy(parseDmarcPolicy(record));
                        break;
                    }
                }
            }

        } catch (NamingException e) {
            System.out.println(
                    "No DMARC record found for: "
                            + client.getDomainName()
            );
        }
    }

    private String parseDmarcPolicy(String record) {
        // The enforcement level lives in the "p=" tag, e.g.
        // "v=DMARC1; p=reject; rua=...". Tags are separated by
        // semicolons, so split on those rather than searching for
        // "p=" directly, which would also match the "sp=" (subdomain
        // policy) tag.
        String[] tags = record.split(";");

        for (String tag : tags) {
            String trimmed = tag.trim();

            if (trimmed.toLowerCase().startsWith("p=")) {
                String value = trimmed.substring(2).trim().toLowerCase();

                switch (value) {
                    case "reject":
                        return "REJECT";
                    case "quarantine":
                        return "QUARANTINE";
                    case "none":
                        return "NONE";
                    default:
                        return "UNKNOWN";
                }
            }
        }

        // A DMARC record without a "p=" tag is malformed; the
        // required policy tag is missing entirely
        return "UNKNOWN";
    }

    private void findDkimRecord(
            InitialDirContext context,
            ClientDomain client,
            String customSelector) {

        // Build the list of selectors to try, checking any
        // analyst-supplied selector first, then the common list
        List<String> selectors = new ArrayList<>();

        if (customSelector != null && !customSelector.isBlank()) {
            selectors.add(customSelector.trim());
        }

        for (String selector : COMMON_DKIM_SELECTORS) {
            if (!selectors.contains(selector)) {
                selectors.add(selector);
            }
        }

        for (String selector : selectors) {
            try {
                // DKIM records live at <selector>._domainkey.<domain>
                Attributes attributes = context.getAttributes(
                        "dns:/" + selector + "._domainkey."
                                + client.getDomainName(),
                        new String[]{"TXT"}
                );

                Attribute txtRecords = attributes.get("TXT");

                if (txtRecords != null && txtRecords.size() > 0) {
                    String record = txtRecords.get(0).toString();

                    client.setDkimRecord(record);
                    client.setDkimSelector(selector);
                    return;
                }

            } catch (NamingException e) {
                // No record under this selector; try the next one
            }
        }

        System.out.println(
                "No DKIM record found for: " + client.getDomainName()
                        + " (checked " + selectors.size()
                        + " selector(s); provide a known selector"
                        + " for a definitive check)"
        );
    }

    private void setAssessment(ClientDomain client) {
        boolean spfFound =
                !client.getSpfRecord().equals("MISSING");

        boolean dmarcFound =
                !client.getDmarcRecord().equals("MISSING");

        boolean dmarcEnforced =
                dmarcFound
                        && (client.getDmarcPolicy().equals("QUARANTINE")
                        || client.getDmarcPolicy().equals("REJECT"));

        String assessment;

        // Determine the basic email-authentication status
        if (spfFound && dmarcFound) {
            assessment = "BASIC EMAIL AUTHENTICATION DETECTED";
        } else if (spfFound || dmarcFound) {
            assessment = "PARTIAL EMAIL AUTHENTICATION DETECTED";
        } else {
            assessment = "EMAIL AUTHENTICATION GAP DETECTED";
        }

        // A published DMARC record that isn't enforcing (p=none, or a
        // malformed record with no usable policy tag) provides
        // visibility but doesn't actually block abuse - call it out
        if (dmarcFound && !dmarcEnforced) {
            assessment += " - DMARC NOT ENFORCED (p="
                    + client.getDmarcPolicy().toLowerCase() + ")";
        }

        client.setAssessment(assessment);
    }
}
