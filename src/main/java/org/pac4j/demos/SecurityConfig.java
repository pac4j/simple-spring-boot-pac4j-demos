package org.pac4j.demos;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.config.method.PrivateKeyJwtClientAuthnMethodConfig;
import org.pac4j.oidc.federation.config.OidcTrustAnchorProperties;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.util.List;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        // configuration of the authentication via the OpenID Federation
        var config = new OidcConfiguration();
        config.setAllowUnsignedIdTokens(true);

        final var rpJwks = config.getRpJwks();
        rpJwks.setJwksPath("file:./metadata/rpoidc.jwks");
        rpJwks.setKid("myrpoidc");
        config.setClientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        final var privateKeyJwtConfig = new PrivateKeyJwtClientAuthnMethodConfig(rpJwks);
        config.setPrivateKeyJWTClientAuthnMethodConfig(privateKeyJwtConfig);

        //config.setRequestObjectSigningAlgorithm(JWSAlgorithm.RS256);

        var federation = config.getFederation();

        federation.setTargetOp("https://localhost:8444/cas/oidc");
        var trust = new OidcTrustAnchorProperties();
        trust.setIssuer("https://localhost:8443/cas/oidc");
        federation.getTrustAnchors().add(trust);

        federation.getJwks().setJwksPath("file:./metadata/rpfede.jwks");
        federation.getJwks().setKid("myrpfede");
        federation.setContactEmails(List.of("jerome@casinthecloud.com"));

        federation.setEntityId(baseUri);

        return new Config(baseUri + "/callback", new OidcClient(config));
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        // the /protected/** URLs require the OIDC authentication
        addSecurity(registry, "OidcClient").addPathPatterns("/protected/**");
    }
}
