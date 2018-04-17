package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.exception.LicenseNotFoundException;

public interface LicenseValidator {

    boolean licenseExists(String licenseLocation);

    boolean licenseExpired(String licenseLocation) throws LicenseNotFoundException;

    boolean licenseViolated(String licenseLocation) throws LicenseNotFoundException;

    boolean validateLimit(String licenseLocation, LicenseModule module, LimitType limitType, int currentValue) throws LicenseNotFoundException;
}
