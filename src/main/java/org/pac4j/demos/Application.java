package org.pac4j.demos;

import org.pac4j.core.config.Config;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.oidc.client.OidcClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class Application {

    @Autowired
    private ProfileManager profileManager;

    @Autowired
    private Config config;

    @RequestMapping("/")
    @ResponseBody
    public String index() {
        return "<h1>Public area</h1><p><a id='protect' href='/protected/index'>Protected area</a></p>"
                + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/protected/index")
    @ResponseBody
    public String secure() {
        return "<h1>Protected area</h1><a href='/'>Home</a><p/>"
                + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping(value = "/.well-known/openid-federation")
    @ResponseBody
    public ResponseEntity<String> oidcFederation() throws HttpAction {
        var oidcClient = (OidcClient) config.getClients().findClient("OidcClient").get();
        var generator = oidcClient.getConfiguration().getFederation().getEntityConfigurationGenerator();
        var entityStatement = generator.generateEntityStatement();
        var contentType = generator.getContentType();
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(entityStatement);
    }
}
