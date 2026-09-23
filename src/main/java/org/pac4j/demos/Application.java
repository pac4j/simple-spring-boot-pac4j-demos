package org.pac4j.demos;

import java.time.Instant;
import java.util.stream.Collectors;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.openid4vp.client.OpenId4VpClient;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.openid4vp.wallet.WalletSimulator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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

import static org.pac4j.openid4vp.util.OpenId4VpConstants.SESSION_TRANSACTION_ID;

@Controller
public class Application {

    @Autowired
    private ProfileManager profileManager;

    @Autowired
    private Config config;

    @Autowired
    private WebContext webContext;

    @Autowired
    private SessionStore sessionStore;

    /** Read only the current browser session's transaction; the callback consumes it. */
    @GetMapping("/vp/status")
    @ResponseBody
    public ResponseEntity<Map<String, String>> vpStatus() {
        final var transactionId = sessionStore.get(webContext, SESSION_TRANSACTION_ID)
            .map(Object::toString).orElse(null);
        String status = "expired";
        if (transactionId != null) {
            final var client = (OpenId4VpClient) config.getClients().findClient("OpenId4VpClient").orElseThrow();
            final var transaction = client.getConfiguration().getTransactionStore().get(transactionId).orElse(null);
            if (transaction != null && transaction.getExpiresAt() != null
                && Instant.now().isBefore(transaction.getExpiresAt())) {
                status = transaction.isAnswered() ? "received" : "pending";
            }
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("status", status));
    }

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

    /** The page driving a presentation, so that the two ways of handing the URL over can be compared. */
    @RequestMapping("/vp")
    @ResponseBody
    public String vp() {
        return vpPage("OpenID4VP presentation, signed request", "/wallet/index", "OpenId4VpClient",
            "<p>The verifier signs its request: the wallet only receives a pointer and fetches the request object.</p>",
            """
            <h2>Cross device &mdash; scan the QR code</h2>
            <p>The wallet is on another device, so nothing can be handed over locally: the URL has to cross the
               gap by itself, and the page asks for it as data instead of being redirected.</p>
            """,
            """
                  Scan the QR code with your wallet. The page continues automatically when the wallet answers.
                  You can also use the callback button below.""", true);
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
            <h2>Cross device &mdash; scan the QR code</h2>
            <p>The URL and QR code contain the complete unsigned request. Scan it with a test wallet that
               accepts the <code>redirect_uri</code> prefix, or use the simulator below.</p>
            """,
            """
                  The very same URL as the link above, only handed over differently.""", false);
    }

    private String vpPage(final String title, final String protectedPath, final String clientName, final String note,
                          final String secondWay, final String urlNote, final boolean automaticCallback) {
        final var simulatorButton = automaticCallback ? "" : """
            <li><button id='play' onclick='play()' disabled>2. play the wallet simulator</button>
                &mdash; it fetches the request object then posts its response, over real HTTP</li>
            """;
        final var simulatorScript = automaticCallback ? "" : """
              async function play() {
                log('browser -> POST /fake-wallet');
                const r = await fetch('/fake-wallet', {method: 'POST',
                  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                  body: 'walletUrl=' + encodeURIComponent(walletUrl)});
                log('browser <- ' + await r.text());
                document.getElementById('back').disabled = false;
              }
            """;
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
              <li><button id='ask' onclick='ask()'>1. ask for the protected page</button>
                  &mdash; the very same request, as an AJAX call. pac4j then answers 401 with the URL in the
                  <code>Location</code> header, leaving the page free to do what it wants with it</li>
              <li><pre id='url' style='white-space:pre-wrap;overflow-wrap:anywhere'>(nothing yet)</pre>
                  <div id='qr' aria-live='polite'></div>
                  %s</li>
              %s
              <li><button id='back' onclick='back()' disabled>3. come back on the callback</button>
                  &mdash; after the wallet has sent its response</li>
            </ol>
            <pre id='log' style='background:#f4f4f4;padding:1em;white-space:pre-wrap'></pre>
            <style>#qr img { max-width:100%%; height:auto; }</style>
            <script src='/js/vendor/qrcode-generator-2.0.4.js'></script>
            <script>
              let walletUrl = null;
              let pollTimer;
              let pollingGeneration = 0;
              let returning = false;
              const automaticCallback = %s;
              const log = m => document.getElementById('log').textContent += m + '\\n';

              async function ask() {
                const button = document.getElementById('ask');
                const qrContainer = document.getElementById('qr');
                button.disabled = true;
                stopPolling();
                returning = false;
                walletUrl = null;
                qrContainer.replaceChildren();
                document.getElementById('url').textContent = '(loading...)';
                const playButton = document.getElementById('play');
                if (playButton) playButton.disabled = true;
                document.getElementById('back').disabled = true;
                try {
                  log('browser -> GET %s (XHR)');
                  const r = await fetch('%s', {headers: {'X-Requested-With': 'XMLHttpRequest'}});
                  walletUrl = r.headers.get('Location');
                  log('browser <- ' + r.status + (walletUrl ? ', Location header received' : ', NO Location header'));
                  document.getElementById('url').textContent = walletUrl || '(no Location header)';
                  if (playButton) playButton.disabled = !walletUrl;
                  document.getElementById('back').disabled = !walletUrl;
                  if (walletUrl) {
                    if (automaticCallback) {
                      log('Waiting for the wallet response...');
                      pollTimer = setTimeout(() => pollStatus(pollingGeneration), 1000);
                    }
                    try {
                      const qr = qrcode(0, 'L');
                      qr.addData(walletUrl);
                      qr.make();
                      qrContainer.innerHTML = qr.createImgTag(4, 16, 'Scan with your wallet');
                    } catch (error) {
                      qrContainer.textContent = 'Unable to generate a QR code. The URL remains available above.';
                    }
                  }
                } catch (error) {
                  document.getElementById('url').textContent = '(request failed)';
                  log('Unable to retrieve the wallet URL. Please try again.');
                } finally {
                  button.disabled = false;
                }
              }

              %s

              function stopPolling() {
                clearTimeout(pollTimer);
                pollingGeneration++;
              }

              async function pollStatus(generation) {
                try {
                  const response = await fetch('/vp/status', {cache: 'no-store', credentials: 'same-origin',
                    signal: AbortSignal.timeout(10000)});
                  if (!response.ok) throw new Error('Status request failed');
                  const result = await response.json();
                  if (generation !== pollingGeneration || returning) return;
                  if (result.status === 'received') {
                    log('Wallet response received. Continuing to the callback...');
                    back();
                  } else if (result.status === 'pending') {
                    pollTimer = setTimeout(() => pollStatus(generation), 1000);
                  } else {
                    stopPolling();
                    document.getElementById('back').disabled = true;
                    log('The transaction expired or is no longer available. Please request a new QR code.');
                  }
                } catch (error) {
                  if (generation !== pollingGeneration || returning) return;
                  stopPolling();
                  log('Unable to check the wallet response. Use the callback button once your wallet has answered.');
                }
              }

              function back() {
                if (returning) return;
                returning = true;
                stopPolling();
                document.getElementById('back').disabled = true;
                document.getElementById('ask').disabled = true;
                window.location = '/callback?client_name=%s';
              }
              window.addEventListener('pagehide', stopPolling);
            </script>
            """.formatted(title, note, protectedPath, secondWay, urlNote, simulatorButton, automaticCallback,
                protectedPath, protectedPath, simulatorScript, clientName);
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

        // encrypted in a "response" parameter, or in clear as a "vp_token" one: whatever the request asked for
        final var answer = simulator.buildResponseParameters(request,
            Map.of("pid", List.of("a-presentation-this-verifier-cannot-validate-yet")));
        final var posted = http.send(HttpRequest.newBuilder(URI.create(request.getResponseUri()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(answer.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"))))
            .build(), HttpResponse.BodyHandlers.ofString());

        return "wallet simulator: " + fetched + ", response posted (" + posted.statusCode() + ")";
    }
}
