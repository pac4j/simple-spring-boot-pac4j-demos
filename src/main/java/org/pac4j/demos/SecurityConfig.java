package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        // configuration of the authentication via the SAML2 protocol
        final var cfg = new SAML2Configuration();
        cfg.getKeystore().setKeystorePath("classpath:samlKeystore.jks");
        cfg.getKeystore().setKeystorePassword("pac4j-demo-passwd");
        cfg.getKeystore().setPrivateKeyPassword("pac4j-demo-passwd");
        cfg.setIdentityProviderMetadataPath("https://casserverpac4j.herokuapp.com/idp/metadata");
        cfg.setServiceProviderEntityId(baseUri + "/callback?client_name=SAML2Client");
        cfg.setServiceProviderMetadataPath("file:metadata/sp-metadata-8080.xml");
        return new Config(baseUri + "/callback", new SAML2Client(cfg));
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        // the /protected/** URLs require the SAML2 authentication
        addSecurity(registry, "SAML2Client").addPathPatterns("/protected/**");
    }
}
