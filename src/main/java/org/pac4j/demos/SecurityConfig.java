package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.UrlResource;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.net.MalformedURLException;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        try {
            final var cfg = new SAML2Configuration(
                    new ClassPathResource("samlKeystore.jks"),
                    "pac4j-demo-passwd",
                    "pac4j-demo-passwd",
                    new UrlResource("https://casserverpac4j.herokuapp.com/idp/metadata"));
            cfg.setMaximumAuthenticationLifetime(3600);
            cfg.setServiceProviderEntityId(baseUri + "/callback?client_name=SAML2Client");
            cfg.setServiceProviderMetadataPath("file:metadata/sp-metadata-8080.xml");
            return new Config(baseUri + "/callback", new SAML2Client(cfg));
        } catch (final MalformedURLException e) {
            throw new TechnicalException(e);
        }
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        addSecurity(registry, "SAML2Client").addPathPatterns("/protected/**");
    }
}
