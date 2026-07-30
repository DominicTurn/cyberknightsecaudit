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

    // Store the domain and audit results
    private String domainName;
    private String spfRecord;
    private String dmarcRecord;
    private String dkimRecord;
    private String dkimSelector;
    private String assessment;

    // Create a new domain with default audit values
    public ClientDomain(String domainName) {
        this.domainName = domainName;
        this.spfRecord = "MISSING";
        this.dmarcRecord = "MISSING";
        this.dkimRecord = "MISSING";
        this.dkimSelector = "NONE";
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

    public String getDkimRecord() {
        return dkimRecord;
    }

    public void setDkimRecord(String dkimRecord) {
        this.dkimRecord = dkimRecord;
    }

    public String getDkimSelector() {
        return dkimSelector;
    }

    public void setDkimSelector(String dkimSelector) {
        this.dkimSelector = dkimSelector;
    }

    public String getAssessment() {
        return assessment;
    }

    public void setAssessment(String assessment) {
        this.assessment = assessment;
    }
}
