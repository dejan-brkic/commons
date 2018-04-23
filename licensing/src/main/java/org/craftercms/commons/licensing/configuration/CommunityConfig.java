package org.craftercms.commons.licensing.configuration;

import org.craftercms.commons.licensing.CommunityLicenseValidator;
import org.craftercms.commons.licensing.LicenseValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("community")
public class CommunityConfig {

    @Bean(name = "crafter.licenseValidator")
    public LicenseValidator licenseValidator() {
        return new CommunityLicenseValidator();
    }
}
