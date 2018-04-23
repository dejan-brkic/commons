package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.exception.LicenseNotFoundException;

public interface LicenseValidator {

    boolean licenseExists();

    boolean licenseExpired() throws LicenseNotFoundException;

    boolean licenseViolated() throws LicenseNotFoundException;

    boolean validateLimit(LicenseModule module, LimitType limitType, int currentValue) throws LicenseNotFoundException;
}
