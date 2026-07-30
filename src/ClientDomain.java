//****************************************************************************//
/*
 * Project: Cyber Knight Sec - Scout
 * Author: Dominic Turner
 * File: ClientDomain.java
 *
 * Stores a domain name, its SPF and DMARC records, and the
 * assessment produced by the DNS audit.
 */
//****************************************************************************//

public class ClientDomain {

    // Default value used when a DNS record has not been found
    private static final String MISSING = "MISSING";

    private String domainName;
    private String spfRecord;
    private String dmarcRecord;
    private String assessment;

    // Create a new domain with default audit values
    public ClientDomain(String domainName) {
        this.domainName = domainName;
        this.spfRecord = MISSING;
        this.dmarcRecord = MISSING;
        this.assessment = "NOT YET ASSESSED";
    }

    public String getDomainName() {
        return domainName;
    }

    public String getSpfRecord() {
        return spfRecord;
    }

    public void setSpfRecord(String spfRecord) {
        this.spfRecord = spfRecord;
    }

    public String getDmarcRecord() {
        return dmarcRecord;
    }

    public void setDmarcRecord(String dmarcRecord) {
        this.dmarcRecord = dmarcRecord;
    }

    public String getAssessment() {
        return assessment;
    }

    public void setAssessment(String assessment) {
        this.assessment = assessment;
    }

    // Return true when no SPF record was found
    public boolean isSpfMissing() {
        return spfRecord.equals(MISSING);
    }

    // Return true when no DMARC record was found
    public boolean isDmarcMissing() {
        return dmarcRecord.equals(MISSING);
    }
}
