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

public class DnsAuditService {

    private static final String SPF_IDENTIFIER = "v=spf1";
    private static final String DMARC_IDENTIFIER = "v=dmarc1";

    public void runAudit(ClientDomain client) {
        InitialDirContext context = null;

        try {
            // Create the DNS connection
            context = new InitialDirContext();

            // Run the SPF and DMARC lookups
            findSpfRecord(context, client);
            findDmarcRecord(context, client);

            // Determine the final assessment
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
            // Request the TXT records from the main domain
            Attributes attributes = context.getAttributes(
                    "dns:/" + client.getDomainName(),
                    new []{"TXT"}
            );

            Attribute txtRecords = attributes.get("TXT");

            if (txtRecords != null) {
                // Search each TXT record for the SPF identifier
                for (int i = 0; i < txtRecords.size(); i++) {
                     record = txtRecords.get(i).toString();

                    // Remove quotation marks added to the DNS response
                    record = record.replace("\"", "");

                    if (record.toLowerCase().contains(SPF_IDENTIFIER)) {
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
                // Search each TXT record for the DMARC identifier
                for (int i = 0; i < txtRecords.size(); i++) {
                    String record = txtRecords.get(i).toString();

                    // Remove quotation marks added to the DNS response
                    record = record.replace("\"", "");

                    if (record.toLowerCase().contains(DMARC_IDENTIFIER)) {
                        client.setDmarcRecord(record);
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

    private void setAssessment(ClientDomain client) {
        boolean spfFound = !client.isSpfMissing();
        boolean dmarcFound = !client.isDmarcMissing();

        if (spfFound && dmarcFound) {
            client.setAssessment(
                    "BASIC EMAIL AUTHENTICATION DETECTED"
            );
        } else if (spfFound || dmarcFound) {
            client.setAssessment(
                    "PARTIAL EMAIL AUTHENTICATION DETECTED"
            );
        } else {
            client.setAssessment(
                    "EMAIL AUTHENTICATION GAP DETECTED"
            );
        }
    }
}
