package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.exception.LicenseNotFoundException;

public class CommunityLicenseValidator implements LicenseValidator {
    @Override
    public boolean licenseExists() {
        return true;
    }

    @Override
    public boolean licenseExpired() throws LicenseNotFoundException {
        return false;
    }

    @Override
    public boolean licenseViolated() throws LicenseNotFoundException {
        return false;
    }

    @Override
    public boolean validateLimit(LicenseModule module, LimitType limitType, int currentValue) throws LicenseNotFoundException {
        return true;
    }
}
