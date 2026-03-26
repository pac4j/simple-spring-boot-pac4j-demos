package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
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
        final var config = new OidcConfiguration();
        config.setDiscoveryURI("https://casserverpac4j.herokuapp.com/oidc/.well-known/openid-configuration");
        config.setClientId("myclient");
        config.setSecret("mysecret");
        config.setAllowUnsignedIdTokens(true);
        return new Config(baseUri + "/callback", new OidcClient(config));
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        addSecurity(registry, "OidcClient").addPathPatterns("/protected/**");
    }
}
