package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.core.config.properties.KeystoreProperties;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.openid4vp.client.OpenId4VpClient;
import org.pac4j.openid4vp.config.ClientIdPrefix;
import org.pac4j.openid4vp.config.CredentialFormat;
import org.pac4j.openid4vp.config.OpenId4VpConfiguration;
import org.pac4j.openid4vp.dcql.CredentialQuery;
import org.pac4j.openid4vp.dcql.DcqlQuery;
import org.pac4j.openid4vp.dcql.EudiPidQuery;
import org.pac4j.openid4vp.verifier.SdJwtVcVerifier;
import org.pac4j.springframework.config.Pac4jSecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.List;
import java.util.UUID;

import static org.pac4j.core.profile.definition.CommonProfileDefinition.FAMILY_NAME;
import static org.pac4j.openid4vp.profile.EudiPidProfileDefinition.AGE_OVER_18;
import static org.pac4j.openid4vp.profile.EudiPidProfileDefinition.GIVEN_NAME;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    /** Not resolvable: no wallet will look it up, and this demo has no DID document to serve. */
    private static final String DID = "did:example:pac4j-demo";

    /** The identifier under which the DID document of this verifier would expose its key. */
    private static final String KID = "pac4j-demo-key";

    /** What this verifier asks for: three attributes of the person identification data, as an mdoc. */
    private static final DcqlQuery DCQL_QUERY = EudiPidQuery.mdoc(GIVEN_NAME, FAMILY_NAME, AGE_OVER_18);

    private static final DcqlQuery FC_DCQL = new DcqlQuery()
            .addCredential(new CredentialQuery("age_over_18", CredentialFormat.MSO_MDOC)
                    .setDoctypeValue("eu.europa.ec.av.1")
                    .addClaim("eu.europa.ec.av.1", AGE_OVER_18));

    private static final String ANIMO_DCQL = "{\n" +
            "  \"credentials\": [\n" +
            "    {\n" +
            "      \"id\": \"0\",\n" +
            "      \"format\": \"dc+sd-jwt\",\n" +
            "      \"meta\": {\n" +
            "        \"vct_values\": [\n" +
            "          \"urn:eudi:pid:1\",\n" +
            "          \"https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0\"\n" +
            "        ]\n" +
            "      },\n" +
            "      \"claims\": [\n" +
            "        {\n" +
            "          \"path\": [\n" +
            "            \"family_name\"\n" +
            "          ],\n" +
            "          \"id\": \"family_name\"\n" +
            "        },\n" +
            "        {\n" +
            "          \"path\": [\n" +
            "            \"given_name\"\n" +
            "          ],\n" +
            "          \"id\": \"given_name\"\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  ],\n" +
            "  \"credential_sets\": [\n" +
            "    {\n" +
            "      \"options\": [\n" +
            "        [\n" +
            "          \"0\"\n" +
            "        ]\n" +
            "      ],\n" +
            "      \"purpose\": \"Please share your EUDI PID\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    // ngrok http 8080
    @Value("${app.base-url:https://nondeficient-untyped-austin.ngrok-free.dev}")
    private String baseUri;

    @Bean
    public Config config() {
        final var fcConfig = new OpenId4VpConfiguration()
            .setClientId("3jLUkxFqNN3_h2OUSoMqfbZpsg99YwjMPKVeu2PDhoc")
            .setClientIdPrefix(ClientIdPrefix.X509_HASH)
            .setDcqlQuery(ANIMO_DCQL)
            .setKeystore(new KeystoreProperties()
                    .setKeystorePath("./metadata/verifier.p12")
                    .setKeyStoreType("PKCS12")
                    .setKeyStoreAlias("rp")
                    .setKeystorePassword("changeit")
                    .setPrivateKeyPassword("changeit"));
        final var sdJwtVcVerifier = new SdJwtVcVerifier();
        sdJwtVcVerifier.setTrustStore(new KeystoreProperties()
                .setKeystorePath("./metadata/animo-sdjwtvc.p12")
                .setKeyStoreType("PKCS12")
                .setKeystorePassword("changeit"));
        try (final var input = Files.newInputStream(Path.of("./metadata/animo-sdjwtvc.crl"))) {
            final var crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(input);
            sdJwtVcVerifier.setCertificateRevocationLists(List.of(crl));
        } catch (final IOException | CertificateException | CRLException e) {
            throw new TechnicalException("Unable to load the Animo certificate revocation list", e);
        }
        fcConfig.addCredentialVerifier(sdJwtVcVerifier);
        // the PID carries no stable identifier: this demo gives a new one at each authentication
        fcConfig.setProfileIdResolver(credentials -> UUID.randomUUID().toString());
        /*final var mdocVerifier = new CredentialVerifier() {
            @Override
            public CredentialFormat getFormat() {
                return CredentialFormat.MSO_MDOC;
            }
            @Override
            public VerifiedCredential verify(String rawCredential, VpTransaction transaction, OpenId4VpConfiguration configuration) {
                throw new TechnicalException("mdoc verification not implemented yet");
            }
        };
        fcConfig.addCredentialVerifier(mdocVerifier);*/

        // the same verifier, reached through the digital credentials API of the browser instead of a URL
        /*final var dcApiConfiguration = new OpenId4VpDcApiConfiguration();
        dcApiConfiguration
            .setClientId(DID)
            .setClientIdPrefix(ClientIdPrefix.DECENTRALIZED_IDENTIFIER)
            .setDcqlQuery(DCQL_QUERY)
            .setJwks(new JwksProperties().setJwksPath("./metadata/openid4vp.jwks").setKid(KID));
        dcApiConfiguration.setExpectedOrigins(List.of(baseUri));
        dcApiConfiguration.addCredentialVerifier(new SdJwtVcVerifier());
        dcApiConfiguration.addCredentialVerifier(mdocVerifier);

        // the same verifier again, with a prefix that cannot sign: the request travels in the wallet URL, and
        // the client identifier is the response URI of each transaction, so there is none to type
        final var unsignedConfiguration = new OpenId4VpConfiguration()
            .setClientIdPrefix(ClientIdPrefix.REDIRECT_URI)
            .setDcqlQuery(DCQL_QUERY);
        unsignedConfiguration.addCredentialVerifier(new SdJwtVcVerifier());
        unsignedConfiguration.addCredentialVerifier(mdocVerifier);
        final var unsignedClient = new OpenId4VpClient(unsignedConfiguration);
        unsignedClient.setName("OpenId4VpUnsignedClient");*/

        final var client = new OpenId4VpClient(fcConfig);
        return new Config(baseUri + "/callback", client); //, new OpenId4VpDcApiClient(dcApiConfiguration), unsignedClient);
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        // the /wallet/** URLs require a presentation from a wallet
        addSecurity(registry, "OpenId4VpClient").addPathPatterns("/wallet/**");
        // the /wallet-dcapi/** URLs require the same presentation, through the digital credentials API
        //addSecurity(registry, "OpenId4VpDcApiClient").addPathPatterns("/wallet-dcapi/**");
        // the /wallet-unsigned/** URLs require the same presentation, asked for without any signature
        //addSecurity(registry, "OpenId4VpUnsignedClient").addPathPatterns("/wallet-unsigned/**");
    }
}
