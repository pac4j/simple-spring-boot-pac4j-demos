package org.pac4j.demos;

import org.pac4j.core.profile.ProfileManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class Application {

    @Autowired
    private ProfileManager profileManager;

    @RequestMapping("/")
    @ResponseBody
    public String index() {
        return "<h1>Public area</h1><p><a href='/protected/index'>Protected area</a></p>"
                + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/protected/index")
    @ResponseBody
    public String secure() {
        return "<h1>Protected area</h1><a href='/'>Home</a><p/>"
                + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }
}
