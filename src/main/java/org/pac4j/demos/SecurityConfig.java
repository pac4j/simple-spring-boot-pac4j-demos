package org.pac4j.demos;

import com.nimbusds.jose.JWSAlgorithm;
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

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

@Configuration
public class SecurityConfig extends Pac4jSecurityConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUri;

    @Bean
    public Config config() {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    @Override
                    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                            throws CertificateException {}

                    @Override
                    public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                            throws CertificateException {}
                }
        };

        SSLContext sc=null;
        try {
            sc = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier validHosts = new HostnameVerifier() {
            @Override
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(validHosts);

        // configuration of the authentication via the OpenID Federation
        var config = new OidcConfiguration();
        final var rpJwks = config.getRpJwks();
        rpJwks.setJwksPath("file:./metadata/rpoidc.jwks");
        rpJwks.setKid("myrpoidc");
        config.setClientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        final var privateKeyJwtConfig = new PrivateKeyJwtClientAuthnMethodConfig(rpJwks);
        config.setPrivateKeyJWTClientAuthnMethodConfig(privateKeyJwtConfig);

        config.setRequestObjectSigningAlgorithm(JWSAlgorithm.RS256);

        var federation = config.getFederation();

        federation.setTargetOp("https://localhost:8444/cas");
        var trust = new OidcTrustAnchorProperties();
        trust.setIssuer("https://localhost:8443/cas");
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
