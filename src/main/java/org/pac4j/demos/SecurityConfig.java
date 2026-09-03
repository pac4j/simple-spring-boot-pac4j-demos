package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.jwt.config.signature.ECSignatureConfiguration;
import org.pac4j.openid4vp.client.OpenId4VpClient;
import org.pac4j.openid4vp.config.ClientIdPrefix;
import org.pac4j.openid4vp.config.OpenId4VpConfiguration;
import org.pac4j.openid4vp.config.WalletInvocationMode;
import org.pac4j.openid4vp.verifier.SdJwtVcVerifier;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        // configuration of the authentication via a wallet, with OpenID4VP: this application is the verifier
        final var configuration = new OpenId4VpConfiguration()
            // the "redirect_uri" prefix identifies this verifier by its own callback URL. A conformant EUDI
            // wallet would refuse it and require a relying party access certificate, with "x509_san_dns"
            .setClientId(baseUri + "/callback")
            .setClientIdPrefix(ClientIdPrefix.REDIRECT_URI)
            .setInvocationMode(WalletInvocationMode.CUSTOM_SCHEME)
            .setDcqlQuery("""
                {"credentials":[{"id":"pid","format":"dc+sd-jwt",
                 "claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["age_over_18"]}]}]}""")
            .setRequestObjectSignatureConfiguration(new ECSignatureConfiguration(newEcKeyPair()));
        configuration.addCredentialVerifier(new SdJwtVcVerifier());

        return new Config(baseUri + "/callback", new OpenId4VpClient(configuration));
    }

    /** A throwaway key for the demo: a real verifier holds the private key of its access certificate. */
    private static KeyPair newEcKeyPair() {
        try {
            final var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        // the /wallet/** URLs require a presentation from a wallet
        addSecurity(registry, "OpenId4VpClient").addPathPatterns("/wallet/**");
    }
}
