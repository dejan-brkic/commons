package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.exception.LicenseNotFoundException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

public class SimpleLicenseValidator implements LicenseValidator {
    @Override
    public boolean licenseExists(String licenseLocation) {
        Resource resource = new ClassPathResource(licenseLocation);
        return resource != null && resource.exists();
    }

    @Override
    public boolean licenseExpired(String licenseLocation) throws LicenseNotFoundException {
        if (licenseExists(licenseLocation)) {
            LicenseDetails licenseDetails = loadLicence(licenseLocation);
            Instant licenseTimestamp = licenseDetails.getContractEndDate().toInstant();
            if (licenseTimestamp.isBefore(Instant.now())) {
                return true;
            }
        } else {
            throw new LicenseNotFoundException();
        }
        return false;
    }

    @Override
    public boolean licenseViolated(String licenseLocation) throws LicenseNotFoundException {
        if (licenseExists(licenseLocation)) {
            LicenseDetails licenseDetails = loadLicence(licenseLocation);
            return licenseDetails == null;
        } else {
            throw new LicenseNotFoundException();
        }
    }

    @Override
    public boolean validateLimit(String licenseLocation, LicenseModule module, LimitType limitType, int currentValue) throws LicenseNotFoundException {
        boolean toRet = false;
        if (licenseExists(licenseLocation)) {
            // TODO: Load license
            LicenseDetails licenseDetails = loadLicence(licenseLocation);
            switch (module) {
                case ENGINE:
                    toRet = engineLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case PROFILE:
                    toRet = profileLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case SOCIAL:
                    toRet = socialLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case STUDIO:
                    toRet = studioLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                default:
                    break;
            }
        } else {
            throw new LicenseNotFoundException();
        }

        return toRet;
    }

    private LicenseDetails loadLicence(String licenseLocation) throws LicenseNotFoundException {
        Resource resource = new ClassPathResource(licenseLocation);
        LicenseDetails licenseDetails = null;
        try (InputStream input = resource.getInputStream()) {
            Yaml yaml = new Yaml();
            licenseDetails = yaml.loadAs(input, LicenseDetails.class);
        } catch (IOException e) {
            throw new LicenseNotFoundException(e);
        }
        return licenseDetails;
    }

    private boolean engineLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        switch (limitType) {
            case SITE:
                EngineLimit engineLimit = licenseDetails.getEngineLimit();
                toRet = currentValue < engineLimit.getNumberOfSites();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean profileLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        ProfileLimit profileLimit = licenseDetails.getProfileLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < profileLimit.getNumberOfSites();
                break;
            case USER:
                toRet = currentValue < profileLimit.getNumberOfUsers();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean socialLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        SocialLimit socialLimit = licenseDetails.getSocialLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < socialLimit.getNumberOfSites();
                break;
            case ITEM:
                toRet = currentValue < socialLimit.getNumberOfItems();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean studioLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        StudioLimit studioLimit = licenseDetails.getStudioLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < studioLimit.getNumberOfSites();
                break;
            case ITEM:
                toRet = currentValue < studioLimit.getNumberOfItems();
                break;
            case USER:
                toRet = currentValue < studioLimit.getNumberOfUsers();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }
}
