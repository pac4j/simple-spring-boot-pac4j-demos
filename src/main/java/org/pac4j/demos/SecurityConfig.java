package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.openid4vp.client.OpenId4VpClient;
import org.pac4j.openid4vp.client.OpenId4VpDcApiClient;
import org.pac4j.openid4vp.config.ClientIdPrefix;
import org.pac4j.openid4vp.dcql.DcqlQuery;
import org.pac4j.openid4vp.dcql.EudiPidQuery;
import static org.pac4j.core.profile.definition.CommonProfileDefinition.FAMILY_NAME;
import static org.pac4j.openid4vp.profile.EudiPidProfileDefinition.AGE_OVER_18;
import static org.pac4j.openid4vp.profile.EudiPidProfileDefinition.GIVEN_NAME;
import org.pac4j.openid4vp.config.OpenId4VpConfiguration;
import org.pac4j.openid4vp.config.OpenId4VpDcApiConfiguration;
import org.pac4j.openid4vp.verifier.SdJwtVcVerifier;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.util.List;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    /** Not resolvable: no wallet will look it up, and this demo has no DID document to serve. */
    private static final String DID = "did:example:pac4j-demo";

    /** The identifier under which the DID document of this verifier would expose its key. */
    private static final String KID = "pac4j-demo-key";

    /** What this verifier asks for: three attributes of the person identification data, as a SD-JWT VC. */
    private static final DcqlQuery DCQL_QUERY = EudiPidQuery.sdJwtVc(GIVEN_NAME, FAMILY_NAME, AGE_OVER_18);

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        // configuration of the authentication via a wallet, with OpenID4VP: this application is the verifier
        final var configuration = new OpenId4VpConfiguration()
            // a decentralized identifier signs its requests without needing a certificate, which keeps this
            // demo runnable. A real EUDI verifier uses "x509_hash" and its relying party access
            // certificate; the "redirect_uri" prefix cannot be used here since its requests cannot be signed
            .setClientId(DID)
            .setClientIdPrefix(ClientIdPrefix.DECENTRALIZED_IDENTIFIER)
            .setDcqlQuery(DCQL_QUERY)
            // the signing key is read from that JWKS, and created there on the first run: an ES256 key,
            // as the profile mandates. A real EUDI verifier would point at a keystore instead, so that the
            // key comes with the relying party access certificate its wallet requires
            .setJwks(new JwksProperties().setJwksPath("./metadata/openid4vp.jwks").setKid(KID));
        configuration.addCredentialVerifier(new SdJwtVcVerifier());

        // the same verifier, reached through the digital credentials API of the browser instead of a URL
        final var dcApiConfiguration = new OpenId4VpDcApiConfiguration();
        dcApiConfiguration
            .setClientId(DID)
            .setClientIdPrefix(ClientIdPrefix.DECENTRALIZED_IDENTIFIER)
            .setDcqlQuery(DCQL_QUERY)
            .setJwks(new JwksProperties().setJwksPath("./metadata/openid4vp.jwks").setKid(KID));
        dcApiConfiguration.setExpectedOrigins(List.of(baseUri));
        dcApiConfiguration.addCredentialVerifier(new SdJwtVcVerifier());

        // the same verifier again, with a prefix that cannot sign: the request travels in the wallet URL, and
        // the client identifier is the response URI of each transaction, so there is none to type
        final var unsignedConfiguration = new OpenId4VpConfiguration()
            .setClientIdPrefix(ClientIdPrefix.REDIRECT_URI)
            .setDcqlQuery(DCQL_QUERY);
        unsignedConfiguration.addCredentialVerifier(new SdJwtVcVerifier());
        final var unsignedClient = new OpenId4VpClient(unsignedConfiguration);
        unsignedClient.setName("OpenId4VpUnsignedClient");

        return new Config(baseUri + "/callback",
            new OpenId4VpClient(configuration), new OpenId4VpDcApiClient(dcApiConfiguration), unsignedClient);
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        // the /wallet/** URLs require a presentation from a wallet
        addSecurity(registry, "OpenId4VpClient").addPathPatterns("/wallet/**");
        // the /wallet-dcapi/** URLs require the same presentation, through the digital credentials API
        addSecurity(registry, "OpenId4VpDcApiClient").addPathPatterns("/wallet-dcapi/**");
        // the /wallet-unsigned/** URLs require the same presentation, asked for without any signature
        addSecurity(registry, "OpenId4VpUnsignedClient").addPathPatterns("/wallet-unsigned/**");
    }
}
