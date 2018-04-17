package org.craftercms.commons.licensing;

import java.io.Serializable;
import java.util.Date;

public class LicenseDetails implements Serializable {

    private static final long serialVersionUID = -8939029515732705776L;

    enum LicenseType {
        PERPETUAL,
        TIME_LIMIT,
        POOLED
    }

    protected String customerName;
    protected String customerId;
    protected Date contractStartDate;
    protected Date contractEndDate;
    protected LicenseType licenseType;
    protected StudioLimit studioLimit;
    protected EngineLimit engineLimit;
    protected ProfileLimit profileLimit;
    protected SocialLimit socialLimit;

    public String getCustomerName() {
        return customerName;
    }

    public void setCustomerName(String customerName) {
        this.customerName = customerName;
    }

    public String getCustomerId() {
        return customerId;
    }

    public void setCustomerId(String customerId) {
        this.customerId = customerId;
    }

    public Date getContractStartDate() {
        return contractStartDate;
    }

    public void setContractStartDate(Date contractStartDate) {
        this.contractStartDate = contractStartDate;
    }

    public Date getContractEndDate() {
        return contractEndDate;
    }

    public void setContractEndDate(Date contractEndDate) {
        this.contractEndDate = contractEndDate;
    }

    public LicenseType getLicenseType() {
        return licenseType;
    }

    public void setLicenseType(LicenseType licenseType) {
        this.licenseType = licenseType;
    }

    public StudioLimit getStudioLimit() {
        return studioLimit;
    }

    public void setStudioLimit(StudioLimit studioLimit) {
        this.studioLimit = studioLimit;
    }

    public EngineLimit getEngineLimit() {
        return engineLimit;
    }

    public void setEngineLimit(EngineLimit engineLimit) {
        this.engineLimit = engineLimit;
    }

    public ProfileLimit getProfileLimit() {
        return profileLimit;
    }

    public void setProfileLimit(ProfileLimit profileLimit) {
        this.profileLimit = profileLimit;
    }

    public SocialLimit getSocialLimit() {
        return socialLimit;
    }

    public void setSocialLimit(SocialLimit socialLimit) {
        this.socialLimit = socialLimit;
    }

}
