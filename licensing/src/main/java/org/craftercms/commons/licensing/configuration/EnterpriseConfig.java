package org.craftercms.commons.licensing.configuration;

import org.craftercms.commons.licensing.LicenseValidator;
import org.craftercms.commons.licensing.SimpleLicenseValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

@Configuration
@Profile("enterprise")
@PropertySources(value = { @PropertySource("classpath:org/craftercms/commons/licensing/license-validator.properties"),
    @PropertySource("classpath:*crafter/licensing/license-validator.properties") })
public class EnterpriseConfig {

    @Value("${crafter.license.location")
    String licenseLocation;

    @Value("${crafter.license.keyLocation")
    String keyLocation;

    @Value("${crafter.license.password")
    String password;

    @Bean
    static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean(name = "crafter.licenseValidator")
    public LicenseValidator licenseValidator() {
        SimpleLicenseValidator licenseValidator = new SimpleLicenseValidator();
        licenseValidator.setLicenseLocation(licenseLocation);
        licenseValidator.setKeyLocation(keyLocation);
        licenseValidator.setPassword(password);
        return licenseValidator;
    }
}
