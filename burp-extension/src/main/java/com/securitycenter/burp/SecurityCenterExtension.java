package com.securitycenter.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.net.URI;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SecurityCenterExtension implements BurpExtension {
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
        "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"
    );
    private static final int MAX_BODY_LENGTH = 256 * 1024;

    /**
     * Where Security Center publishes the backend it is actually using.
     *
     * Burp is a separate application: it cannot read VS Code settings, and the
     * address it needs is not a constant — in Auto mode the extension starts a
     * local service on whatever port is free, and in Remote mode the backend is
     * not local at all. So the connector reads the address instead of assuming
     * it. Nothing here hard-codes a port.
     */
    private static final Path DISCOVERY_FILE =
        Path.of(System.getProperty("user.home"), ".security-center", "backend.json");
    private static final String EXPECTED_SERVICE = "security-center-backend";

    private MontoyaApi api;
    private final HttpClient httpClient = HttpClient.newBuilder().proxy(new ProxySelector() {
        @Override
        public List<Proxy> select(URI uri) {
            return List.of(Proxy.NO_PROXY);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException error) {
            // The next direct request will report its own connection error.
        }
    }).build();
    private final JTextField backendUrl = new JTextField("", 28);
    private final JPasswordField apiKey = new JPasswordField(16);
    private final JLabel status = new JLabel("Prêt — sélectionnez une requête dans Proxy ou Repeater.");
    private final JCheckBox automaticCapture = new JCheckBox("Capture automatique : local et cible autorisée", true);
    private final Set<String> sentFingerprints = ConcurrentHashMap.newKeySet();
    /**
     * The Dynamic Security target Security Center authorised, published in the
     * discovery file. Only these origins — besides loopback — are captured.
     */
    private final Set<String> captureOrigins = ConcurrentHashMap.newKeySet();
    private Timer heartbeat;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("Security Center Connector");
        api.userInterface().registerContextMenuItemsProvider(new SecurityCenterMenu());
        api.proxy().registerResponseHandler(new AutomaticProxyCapture());
        api.userInterface().registerSuiteTab("Security Center", createSuiteTab());
        loadDiscoveredBackend(true);
        heartbeat = new Timer(5000, event -> sendHeartbeat());
        heartbeat.setInitialDelay(0);
        heartbeat.start();
        api.extension().registerUnloadingHandler(() -> {
            if (heartbeat != null) heartbeat.stop();
            sentFingerprints.clear();
            api.logging().logToOutput("Security Center Connector déchargé proprement.");
        });
        api.logging().logToOutput("Security Center Connector chargé — capture automatique locale activée.");
    }

    private Component createSuiteTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        JPanel connection = new JPanel(new FlowLayout(FlowLayout.LEFT));
        connection.add(new JLabel("Backend local :"));
        connection.add(backendUrl);
        connection.add(new JLabel("Clé API :"));
        apiKey.setToolTipText("Laissez vide si SECURITY_CENTER_API_KEY n’est pas configurée.");
        connection.add(apiKey);
        JButton test = new JButton("Tester la connexion");
        test.addActionListener(event -> testConnection());
        connection.add(test);
        JButton diagnostic = new JButton("Envoyer un test");
        diagnostic.addActionListener(event -> sendDiagnosticScenario());
        connection.add(diagnostic);
        JButton rediscover = new JButton("Recharger la configuration");
        rediscover.setToolTipText("Relit l'adresse publiée par Security Center, par exemple après un changement de port.");
        rediscover.addActionListener(event -> loadDiscoveredBackend(true));
        connection.add(rediscover);
        connection.add(automaticCapture);
        panel.add(connection, BorderLayout.NORTH);
        panel.add(status, BorderLayout.CENTER);
        return panel;
    }

    /**
     * Reads the address Security Center published, and fills the form with it.
     *
     * A missing file is not an error: it means Security Center has not run yet
     * on this machine. The message says so, instead of leaving the connector
     * pointing at a port that may belong to something else entirely.
     */
    private void loadDiscoveredBackend(boolean announce) {
        try {
            if (!Files.isReadable(DISCOVERY_FILE)) {
                if (announce) {
                    setStatus("Ouvrez Security Center dans VS Code : le connecteur y lira l'adresse du backend.");
                }
                return;
            }
            String content = Files.readString(DISCOVERY_FILE, StandardCharsets.UTF_8);
            if (!EXPECTED_SERVICE.equals(jsonField(content, "service"))) {
                if (announce) setStatus("Le fichier de découverte ne décrit pas un backend Security Center.");
                return;
            }
            String url = jsonField(content, "url");
            String key = jsonField(content, "api_key");
            if (!url.isBlank()) backendUrl.setText(url);
            // The key travels with the address: both come from the same
            // installation, and neither is written to the Burp log.
            if (!key.isBlank() && !key.equals(configuredApiKey())) apiKey.setText(key);
            Set<String> origins = new java.util.HashSet<>();
            for (String entry : jsonStringArray(content, "capture_origins")) {
                try { origins.add(originOf(URI.create(entry))); } catch (RuntimeException ignored) { /* invalid entries are not captured */ }
            }
            captureOrigins.retainAll(origins);
            captureOrigins.addAll(origins);
            if (announce) setStatus("Backend Security Center : " + backendUrl.getText().trim()
                + (captureOrigins.isEmpty() ? "" : " — cible autorisée : " + String.join(", ", captureOrigins)));
        } catch (IOException error) {
            if (announce) setStatus("Configuration du backend illisible — " + error.getMessage());
        }
    }

    /** One string field of the discovery file. The file is small, flat, and written by us. */
    private static String jsonField(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return matcher.find() ? matcher.group(1) : "";
    }

    /** One array of strings of the discovery file, or an empty list. */
    private static List<String> jsonStringArray(String json, String field) {
        Matcher array = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\\[([^\\]]*)\\]").matcher(json);
        List<String> values = new ArrayList<>();
        if (!array.find()) return values;
        Matcher item = Pattern.compile("\"([^\"]*)\"").matcher(array.group(1));
        while (item.find()) values.add(item.group(1));
        return values;
    }

    /** scheme://host:port, with the default port made explicit, so both sides compare equal. */
    private static String originOf(URI uri) {
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        int port = uri.getPort() >= 0 ? uri.getPort() : ("https".equals(scheme) ? 443 : 80);
        return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + ":" + port;
    }

    private final class AutomaticLocalCapture implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            String requestUrl = response.initiatingRequest().url();
            if (automaticCapture.isSelected() && isCapturableUrl(requestUrl) && !isBackendUrl(requestUrl)) {
                HttpRequestResponse pair = HttpRequestResponse.httpRequestResponse(
                    response.initiatingRequest(),
                    response
                );
                String fingerprint = fingerprint(pair);
                if (sentFingerprints.add(fingerprint)) {
                    if (sentFingerprints.size() > 5000) sentFingerprints.clear();
                    sendToSecurityCenter(pair, "automatic-capture");
                }
            }
            return ResponseReceivedAction.continueWith(response);
        }
    }

    private final class AutomaticProxyCapture implements ProxyResponseHandler {
        @Override
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
            captureProxyResponse(response);
            return ProxyResponseReceivedAction.continueWith(response);
        }

        @Override
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
            return ProxyResponseToBeSentAction.continueWith(response);
        }
    }

    private void captureProxyResponse(InterceptedResponse response) {
        String requestUrl = response.initiatingRequest().url();
        if (!automaticCapture.isSelected() || !isCapturableUrl(requestUrl) || isBackendUrl(requestUrl)) return;
        HttpRequestResponse pair = HttpRequestResponse.httpRequestResponse(response.initiatingRequest(), response);
        String fingerprint = fingerprint(pair);
        if (sentFingerprints.add(fingerprint)) {
            if (sentFingerprints.size() > 5000) sentFingerprints.clear();
            sendToSecurityCenter(pair, "automatic-capture");
        }
    }

    private final class SecurityCenterMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
            event.messageEditorRequestResponse().ifPresent(editor -> {
                if (selected.isEmpty()) selected.add(editor.requestResponse());
            });
            JMenuItem send = new JMenuItem("Envoyer vers Security Center");
            send.setEnabled(!selected.isEmpty());
            send.addActionListener(action -> selected.forEach(pair -> sendToSecurityCenter(pair, "manual-selection")));
            return List.of(send);
        }
    }

    private void testConnection() {
        setStatus("Connexion au backend…");
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
            .uri(URI.create(normalizedBackend() + "/api/v1/integrations/burp/status"))
            .header("X-Security-Center-Key", configuredApiKey())
            .GET()
            .build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenAccept(response -> setStatus(response.statusCode() == 200
                ? "Connecté à Security Center."
                : "Backend HTTP " + response.statusCode()))
            .exceptionally(error -> {
                setStatus("Connexion impossible : " + rootMessage(error));
                return null;
            });
    }

    private void sendDiagnosticScenario() {
        String payload = "{"
            + "\"name\":\"Security Center connector diagnostic\","
            + "\"source\":\"burp\","
            + "\"request\":{\"method\":\"GET\",\"url\":\"http://127.0.0.1:3000/\","
            + "\"headers\":{},\"body\":\"\",\"sensitive_headers\":[]},"
            + "\"response\":{\"statusCode\":200,\"headers\":{},\"body\":\"diagnostic\",\"bodySha256\":\"\"},"
            + "\"tags\":[\"burp\",\"diagnostic\",\"local\"]}";
        setStatus("Envoi du test Security Center…");
        postScenarioPayload(payload, "Test transmis à Security Center.");
    }

    private void postScenarioPayload(String payload, String successMessage) {
        CompletableFuture.runAsync(() -> {
            try {
                byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
                postJsonDirect("/api/v1/integrations/burp/requests", payload, 201);
                setStatus(successMessage + " (" + payloadBytes.length + " octets)");
                api.logging().logToOutput(successMessage + " (" + payloadBytes.length + " octets)");
            } catch (Exception error) {
                setStatus("Test impossible : " + rootMessage(error));
                api.logging().logToError("Test impossible : " + rootMessage(error));
            }
        });
    }

    private void sendHeartbeat() {
        // Security Center republishes the address, the key and the authorised
        // target when they change: each beat follows the current values.
        loadDiscoveredBackend(false);
        try {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(normalizedBackend() + "/api/v1/integrations/burp/heartbeat"))
                .header("X-Security-Center-Key", configuredApiKey())
                .POST(BodyPublishers.noBody())
                .build();
            httpClient.sendAsync(request, BodyHandlers.discarding())
                .thenAccept(response -> {
                    if (response.statusCode() == 401) {
                        setStatus("Clé API refusée par Security Center — cliquez « Recharger la configuration ».");
                    } else if (response.statusCode() >= 400) {
                        setStatus("Heartbeat refusé : backend HTTP " + response.statusCode());
                    }
                })
                .exceptionally(error -> {
                    setStatus("Backend Security Center injoignable : " + rootMessage(error));
                    return null;
                });
        } catch (RuntimeException error) {
            // Le prochain heartbeat réessaiera après correction de l’URL ou redémarrage du backend.
            setStatus("Adresse du backend invalide : " + rootMessage(error));
        }
    }

    private void sendToSecurityCenter(HttpRequestResponse requestResponse, String captureMode) {
        CompletableFuture.runAsync(() -> {
            try {
                String payload = scenarioJson(requestResponse, captureMode);
                byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
                api.logging().logToOutput("Envoi Security Center : " + payloadBytes.length + " octets JSON pour "
                    + requestResponse.request().method() + " " + requestResponse.request().url());
                postJsonDirect("/api/v1/integrations/burp/requests", payload, 201);
                setStatus("Requête envoyée vers Security Center : " + requestResponse.request().method()
                    + " " + requestResponse.request().url());
                api.logging().logToOutput("Requête transmise : " + requestResponse.request().url());
            } catch (Exception error) {
                setStatus("Envoi impossible : " + rootMessage(error));
                api.logging().logToError("Envoi impossible : " + rootMessage(error));
            }
        });
    }

    private String postJsonDirect(String endpoint, String payload, int expectedStatus) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection connection = (HttpURLConnection) new URL(normalizedBackend() + endpoint)
            .openConnection(Proxy.NO_PROXY);
        connection.setRequestMethod("POST");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(10000);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        connection.setRequestProperty("X-Security-Center-Key", configuredApiKey());
        connection.setFixedLengthStreamingMode(bytes.length);
        try (var output = connection.getOutputStream()) {
            output.write(bytes);
            output.flush();
        }
        int statusCode = connection.getResponseCode();
        var stream = statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String responseBody = stream == null ? "" : new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        connection.disconnect();
        if (statusCode != expectedStatus) {
            throw new IllegalStateException("Backend HTTP " + statusCode + " : " + responseBody);
        }
        return responseBody;
    }

    private String scenarioJson(HttpRequestResponse pair, String captureMode) {
        HttpRequest request = pair.request();
        validateCapturableUrl(request.url());
        HttpResponse response = pair.response();
        String requestBody = limited(request.bodyToString());
        String responseBody = response == null ? "" : limited(response.bodyToString());
        StringBuilder json = new StringBuilder();
        json.append("{\"name\":\"").append(json(request.method() + " " + URI.create(request.url()).getPath())).append("\",");
        json.append("\"source\":\"burp\",\"request\":{");
        json.append("\"method\":\"").append(json(request.method())).append("\",");
        json.append("\"url\":\"").append(json(request.url())).append("\",");
        json.append("\"headers\":").append(headersJson(request.headers())).append(",");
        json.append("\"body\":\"").append(json(requestBody)).append("\",");
        json.append("\"sensitive_headers\":").append(sensitiveHeaderNames(request.headers())).append("},");
        if (response == null) {
            json.append("\"response\":null,");
        } else {
            json.append("\"response\":{");
            json.append("\"statusCode\":").append(response.statusCode()).append(",");
            json.append("\"headers\":").append(headersJson(response.headers())).append(",");
            json.append("\"body\":\"").append(json(responseBody)).append("\",");
            json.append("\"bodySha256\":\"").append(sha256(responseBody)).append("\"},");
        }
        json.append("\"tags\":[\"burp\",\"").append(json(captureMode)).append("\",\"local\"]}");
        return json.toString();
    }

    private static String headersJson(List<HttpHeader> headers) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (HttpHeader header : headers) {
            if (!first) json.append(",");
            first = false;
            String name = header.name().toLowerCase(Locale.ROOT);
            String value = SENSITIVE_HEADERS.contains(name) ? "[REDACTED]" : header.value();
            json.append("\"").append(json(name)).append("\":\"").append(json(value)).append("\"");
        }
        return json.append("}").toString();
    }

    private static String sensitiveHeaderNames(List<HttpHeader> headers) {
        return headers.stream()
            .map(header -> header.name().toLowerCase(Locale.ROOT))
            .filter(SENSITIVE_HEADERS::contains)
            .distinct()
            .map(name -> "\"" + json(name) + "\"")
            .reduce((left, right) -> left + "," + right)
            .map(value -> "[" + value + "]")
            .orElse("[]");
    }

    /**
     * Loopback, or the Dynamic Security target Security Center authorised.
     *
     * The remote lab target used to be dropped here silently: every request to
     * it passed through Burp and never reached Security Center.
     */
    private void validateCapturableUrl(String value) {
        URI uri = URI.create(value);
        String host = uri.getHost();
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Seules les URL HTTP/HTTPS sont acceptées.");
        }
        if (host != null && Set.of("127.0.0.1", "localhost", "::1").contains(host)) return;
        if (host != null && captureOrigins.contains(originOf(uri))) return;
        throw new IllegalArgumentException("Hors périmètre : ni locale, ni cible Dynamic Security autorisée dans Security Center.");
    }

    private boolean isCapturableUrl(String value) {
        try {
            validateCapturableUrl(value);
            return true;
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static String fingerprint(HttpRequestResponse pair) {
        String responseStatus = pair.response() == null ? "" : String.valueOf(pair.response().statusCode());
        return sha256(pair.request().method() + "\n" + pair.request().url() + "\n"
            + pair.request().bodyToString() + "\n" + responseStatus);
    }

    private String normalizedBackend() {
        return backendUrl.getText().trim().replaceAll("/+$", "");
    }

    private String configuredApiKey() {
        return new String(apiKey.getPassword()).trim();
    }

    private boolean isBackendUrl(String value) {
        try {
            URI candidate = URI.create(value);
            URI backend = URI.create(normalizedBackend());
            return candidate.getHost() != null
                && candidate.getHost().equalsIgnoreCase(backend.getHost())
                && effectivePort(candidate) == effectivePort(backend);
        } catch (RuntimeException error) {
            return false;
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private void setStatus(String text) {
        SwingUtilities.invokeLater(() -> status.setText(text));
    }

    private static String limited(String value) {
        String text = value == null ? "" : value;
        return text.length() <= MAX_BODY_LENGTH ? text : text.substring(0, MAX_BODY_LENGTH) + "\n[TRUNCATED]";
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static String json(String value) {
        StringBuilder escaped = new StringBuilder();
        for (char character : String.valueOf(value).toCharArray()) {
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) escaped.append(String.format("\\u%04x", (int) character));
                    else escaped.append(character);
                }
            }
        }
        return escaped.toString();
    }

    private static String rootMessage(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null) current = current.getCause();
        return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
    }
}
