package org.pac4j.demos;

import java.util.stream.Collectors;
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
            + "<p><a href='/vp'>Protected area (wallet by URL, signed request)</a></p>"
            + "<p><a href='/vp-unsigned'>Protected area (wallet by URL, unsigned request)</a></p>"
            + "<p><a href='/dcapi'>Protected area (wallet through the digital credentials API)</a></p>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/wallet-unsigned/index")
    @ResponseBody
    public String walletUnsigned() {
        return "<h1>Wallet protected area, unsigned request</h1><a href='/'>Home</a><p/>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/wallet-dcapi/index")
    @ResponseBody
    public String walletDcApi() {
        return "<h1>Wallet protected area, through the digital credentials API</h1><a href='/'>Home</a><p/>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    @RequestMapping("/wallet/index")
    @ResponseBody
    public String wallet() {
        return "<h1>Wallet protected area</h1><a href='/'>Home</a><p/>"
            + "<p><a href='/logout'>Logout</a></p>" + profileManager.getProfiles();
    }

    /** The page driving a presentation, step by step, so that every exchange can be watched. */
    /** The page driving a presentation, so that the two ways of handing the URL over can be compared. */
    @RequestMapping("/vp")
    @ResponseBody
    public String vp() {
        return vpPage("OpenID4VP presentation, signed request", "/wallet/index", "OpenId4VpClient",
            "<p>The verifier signs its request: the wallet only receives a pointer and fetches the request object.</p>",
            """
            <h2>Cross device &mdash; the same URL is displayed</h2>
            <p>The wallet is on another device, so nothing can be handed over locally: the URL has to cross the
               gap by itself, and the page asks for it as data instead of being redirected.</p>
            """,
            """
                  A real cross device flow renders this URL as a QR code, which the wallet of another device
                  scans. This demo shows it as text instead, to make the point that it is the very same URL as
                  the link above &mdash; only handed over differently.""",
            """
                  . <label><input type='checkbox' id='supportsPost' checked> this wallet supports
                  <code>request_uri_method=post</code></label> &mdash; the verifier only announces it, the
                  wallet decides: uncheck to see a wallet fall back to a plain GET""");
    }

    /** The same page for a request the verifier cannot sign: the request travels in the wallet URL itself. */
    @RequestMapping("/vp-unsigned")
    @ResponseBody
    public String vpUnsigned() {
        return vpPage("OpenID4VP presentation, unsigned request", "/wallet-unsigned/index", "OpenId4VpUnsignedClient",
            "<p>The <code>redirect_uri</code> prefix gives the wallet no key to trust, so the request <b>cannot</b> be "
            + "signed: its parameters travel in the wallet URL, there is no request object to fetch. Notice how much "
            + "longer the URL gets, the DCQL query and the client metadata being carried whole. And look at the "
            + "<code>client_id</code>: it is the response URI of this very transaction, since with this prefix the "
            + "identifier <i>is</i> the URI the wallet may answer to. Nothing was configured for it.</p>",
            """
            <h2>From the page &mdash; the same URL is fetched</h2>
            <p><b>No cross device here.</b> An unsigned request must not be shown as a QR code: the wallet cannot
               authenticate the verifier, so nothing would tell the person scanning it who is asking, and the
               answer would be posted to whoever displayed the code. The page only fetches the URL to hand it to
               the simulator.</p>
            """,
            """
                  The very same URL as the link above, only handed over differently.""", "");
    }

    private String vpPage(final String title, final String protectedPath, final String clientName, final String note,
                          final String secondWay, final String urlNote, final String playNote) {
        return """
            <h1>%s</h1>
            %s
            <p><a href='/'>Home</a></p>

            <h2>Same device &mdash; the URL is followed</h2>
            <p><a href='%s'>Ask for the protected page</a>
               &mdash; a plain link, no JavaScript at all.</p>
            <p>The application answers a 302 whose <code>Location</code> is the <code>openid4vp://</code> URL,
               and the browser hands it to the operating system. On a phone holding a wallet, the wallet opens
               and the presentation carries on there. <b>On a desktop no application claims that scheme, so the
               browser refuses it</b> &mdash; that dead end is precisely what this link demonstrates.</p>

            %s
            <ol>
              <li><button onclick='ask()'>1. ask for the protected page</button>
                  &mdash; the very same request, as an AJAX call. pac4j then answers 401 with the URL in the
                  <code>Location</code> header, leaving the page free to do what it wants with it</li>
              <li><pre id='url' style='white-space:pre-wrap'>(nothing yet)</pre>
                  %s</li>
              <li><button id='play' onclick='play()' disabled>2. play the wallet simulator</button>
                  &mdash; it fetches the request object then posts its response, over real HTTP%s</li>
              <li><button id='back' onclick='back()' disabled>3. come back on the callback</button>
                  &mdash; the only leg carrying a session</li>
            </ol>
            <pre id='log' style='background:#f4f4f4;padding:1em;white-space:pre-wrap'></pre>
            <script>
              let walletUrl = null;
              const log = m => document.getElementById('log').textContent += m + '\\n';

              async function ask() {
                log('browser -> GET %s (XHR)');
                const r = await fetch('%s', {headers: {'X-Requested-With': 'XMLHttpRequest'}});
                walletUrl = r.headers.get('Location');
                log('browser <- ' + r.status + (walletUrl ? ', Location header received' : ', NO Location header'));
                document.getElementById('url').textContent = walletUrl || '(no Location header)';
                document.getElementById('play').disabled = !walletUrl;
              }

              async function play() {
                log('browser -> POST /fake-wallet');
                const r = await fetch('/fake-wallet', {method: 'POST',
                  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                  body: 'walletUrl=' + encodeURIComponent(walletUrl)
                    + '&supportsPost=' + (document.getElementById('supportsPost')?.checked ?? true)});
                log('browser <- ' + await r.text());
                document.getElementById('back').disabled = false;
              }

              function back() { window.location = '/callback?client_name=%s'; }
            </script>
            """.formatted(title, note, protectedPath, secondWay, urlNote, playNote, protectedPath, protectedPath, clientName);
    }

    /** The page driving a presentation through the digital credentials API of the browser. */
    @RequestMapping("/dcapi")
    @ResponseBody
    public String dcapi() {
        return """
            <h1>OpenID4VP through the digital credentials API</h1>
            <p><a href='/'>Home</a></p>
            <p>The browser mediates the whole exchange: it asks which wallet to use, hands it the request along
               with the origin it authenticated, and returns the answer to this page. Nothing is posted between
               the wallet and the application, so the page never leaves and keeps its session.</p>
            <ol>
              <li><button onclick='ask()'>1. ask for the protected page</button>
                  &mdash; a plain call, <b>not</b> marked as AJAX: the answer is a 200 carrying the request
                  object as JSON, which no <code>Location</code> header could hold</li>
              <li><pre id='req' style='white-space:pre-wrap;word-break:break-all'>(nothing yet)</pre></li>
              <li><button id='call' onclick='call()' disabled>2. call navigator.credentials.get()</button>
                  &mdash; <b>this will fail on this machine</b>: no wallet is registered with the browser. The
                  failure is the demonstration</li>
              <li><button id='fake' onclick='fake()' disabled>3. post a made-up answer</button>
                  &mdash; to see the single leg of this binding reach the verifier, with its session</li>
            </ol>
            <pre id='log' style='background:#f4f4f4;padding:1em;white-space:pre-wrap'></pre>
            <script>
              let request = null;
              const log = m => document.getElementById('log').textContent += m + '\\n';

              async function ask() {
                log('browser -> GET /wallet-dcapi/index');
                const r = await fetch('/wallet-dcapi/index');
                const body = await r.json();
                request = body.request;
                log('browser <- ' + r.status + ', request object of ' + request.length + ' characters');
                document.getElementById('req').textContent = request;
                document.getElementById('call').disabled = false;
                document.getElementById('fake').disabled = false;
              }

              async function call() {
                if (!navigator.credentials || !window.DigitalCredential) {
                  log('this browser has no digital credentials API');
                  return;
                }
                try {
                  const credential = await navigator.credentials.get({digital: {requests: [
                    {protocol: 'openid4vp-v1-signed', data: {request: request}}]}});
                  log('wallet answered, posting it back');
                  await post(credential.data.response);
                } catch (e) {
                  log('no wallet answered: ' + e);
                }
              }

              async function fake() { await post('a-made-up-answer-the-verifier-cannot-decrypt'); }

              async function post(response) {
                const r = await fetch('/callback?client_name=OpenId4VpDcApiClient', {method: 'POST',
                  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                  body: 'response=' + encodeURIComponent(response)});
                log('browser <- ' + r.status + ' from the callback');
              }
            </script>
            """;
    }

    /**
     * Plays the wallet, over real HTTP against this very application: it fetches the request object, then
     * posts a response. Neither leg carries a session, which is the whole point.
     */
    @PostMapping("/fake-wallet")
    @ResponseBody
    public String fakeWallet(@RequestParam("walletUrl") final String walletUrl,
                             @RequestParam(value = "supportsPost", defaultValue = "true") final boolean supportsPost)
        throws Exception {
        final var simulator = new WalletSimulator();
        final var http = HttpClient.newHttpClient();

        // a signed request is fetched from its request URI; an unsigned one is the wallet URL itself
        final String fetched;
        final org.pac4j.openid4vp.wallet.WalletRequest request;
        if (simulator.hasRequestUri(walletUrl)) {
            final var requestUri = URI.create(simulator.readRequestUri(walletUrl));
            if (simulator.postsToRequestUri(walletUrl) && supportsPost) {
                // the verifier lets the wallet say what it supports first: the request object is built for it
                final var walletNonce = simulator.generateWalletNonce();
                final var body = simulator.buildRequestUriPostParameters(walletNonce).entrySet().stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
                final var served = http.send(HttpRequest.newBuilder(requestUri)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/oauth-authz-req+jwt")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
                request = simulator.readRequestObject(served.body(), walletNonce);
                fetched = "capabilities posted, request object received (" + served.statusCode() + ")";
            } else {
                // a wallet which does not support the post method ignores the announcement and fetches, as the spec says
                final var served = http.send(HttpRequest.newBuilder(requestUri).GET().build(), HttpResponse.BodyHandlers.ofString());
                request = simulator.readRequestObject(served.body());
                fetched = "request object fetched with a plain GET (" + served.statusCode() + ")";
            }
        } else {
            request = simulator.readRequestParameters(walletUrl);
            fetched = "request read from the URL itself, nothing to fetch";
        }

        final var response = simulator.buildResponse(request,
            Map.of("pid", List.of("a-presentation-this-verifier-cannot-validate-yet")));
        final var posted = http.send(HttpRequest.newBuilder(URI.create(request.getResponseUri()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(
                "response=" + URLEncoder.encode(response, StandardCharsets.UTF_8)))
            .build(), HttpResponse.BodyHandlers.ofString());

        return "wallet simulator: " + fetched + ", response posted (" + posted.statusCode() + ")";
    }
}
