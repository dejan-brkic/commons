package org.craftercms.commons.licensing.configuration;

import org.craftercms.commons.licensing.LicenseValidator;
import org.craftercms.commons.licensing.SimpleLicenseValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("enterprise")
public class EnterpriseConfig {

    @Bean(name = "crafter.licenseValidator")
    public LicenseValidator licenseValidator() {
        LicenseValidator licenseValidator = new SimpleLicenseValidator();
        return licenseValidator;
    }
}
