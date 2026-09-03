package org.pac4j.demos;

import org.pac4j.core.profile.ProfileManager;
import org.pac4j.openid4vp.wallet.WalletSimulator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Controller
public class Application {

    @Autowired
    private ProfileManager profileManager;

    @RequestMapping("/")
    @ResponseBody
    public String index() {
        return "<h1>Public area</h1>"
            + "<p><a href='/vp'>Protected area (wallet, OpenID4VP)</a></p>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/wallet/index")
    @ResponseBody
    public String wallet() {
        return "<h1>Wallet protected area</h1><a href='/'>Home</a><p/>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    /** The page driving a presentation, step by step, so that every exchange can be watched. */
    @RequestMapping("/vp")
    @ResponseBody
    public String vp() {
        return """
            <h1>OpenID4VP presentation</h1>
            <p><a href='/'>Home</a></p>
            <ol>
              <li><button onclick='ask()'>1. ask for the protected page</button>
                  &mdash; an AJAX call, answered 401 with the wallet URL in the Location header</li>
              <li><pre id='url' style='white-space:pre-wrap'>(nothing yet)</pre>
                  a real wallet would be handed this URL, as a deep link or as a QR code</li>
              <li><button id='play' onclick='play()' disabled>2. play the wallet simulator</button>
                  &mdash; it fetches the request object then posts its response, over real HTTP</li>
              <li><button id='back' onclick='back()' disabled>3. come back on the callback</button>
                  &mdash; the only leg carrying a session</li>
            </ol>
            <pre id='log' style='background:#f4f4f4;padding:1em;white-space:pre-wrap'></pre>
            <script>
              let walletUrl = null;
              const log = m => document.getElementById('log').textContent += m + '\\n';

              async function ask() {
                log('browser -> GET /wallet/index (XHR)');
                const r = await fetch('/wallet/index', {headers: {'X-Requested-With': 'XMLHttpRequest'}});
                walletUrl = r.headers.get('Location');
                log('browser <- ' + r.status + (walletUrl ? ', Location header received' : ', NO Location header'));
                document.getElementById('url').textContent = walletUrl || '(no Location header)';
                document.getElementById('play').disabled = !walletUrl;
              }

              async function play() {
                log('browser -> POST /fake-wallet');
                const r = await fetch('/fake-wallet', {method: 'POST',
                  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                  body: 'walletUrl=' + encodeURIComponent(walletUrl)});
                log('browser <- ' + await r.text());
                document.getElementById('back').disabled = false;
              }

              function back() { window.location = '/callback?client_name=OpenId4VpClient'; }
            </script>
            """;
    }

    /**
     * Plays the wallet, over real HTTP against this very application: it fetches the request object, then
     * posts a response. Neither leg carries a session, which is the whole point.
     */
    @PostMapping("/fake-wallet")
    @ResponseBody
    public String fakeWallet(@RequestParam("walletUrl") final String walletUrl) throws Exception {
        final var simulator = new WalletSimulator();
        final var http = HttpClient.newHttpClient();

        final var requestUri = simulator.readRequestUri(walletUrl);
        final var served = http.send(HttpRequest.newBuilder(URI.create(requestUri)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        final var request = simulator.readRequestObject(served.body());

        final var response = simulator.buildResponse(request,
            Map.of("pid", List.of("a-presentation-this-verifier-cannot-validate-yet")));
        final var posted = http.send(HttpRequest.newBuilder(URI.create(request.getResponseUri()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(
                "response=" + URLEncoder.encode(response, StandardCharsets.UTF_8)))
            .build(), HttpResponse.BodyHandlers.ofString());

        return "wallet simulator: request object fetched (" + served.statusCode()
            + "), response posted (" + posted.statusCode() + ")";
    }
}
