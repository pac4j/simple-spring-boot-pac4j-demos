package org.pac4j.demos;

import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Value("${cas.login-url:https://casserverpac4j.herokuapp.com/login}")
    private String casLoginUrl;

    @Bean
    public Config config() {
        return new Config(baseUri + "/callback", new CasClient(new CasConfiguration(casLoginUrl)));
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        addSecurity(registry, "CasClient").addPathPatterns("/protected/**");
    }
}
