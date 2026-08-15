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
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class SecurityCenterExtension implements BurpExtension {
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
        "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"
    );
    private static final int MAX_BODY_LENGTH = 256 * 1024;

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
    private final JTextField backendUrl = new JTextField("http://127.0.0.1:8765", 28);
    private final JPasswordField apiKey = new JPasswordField(16);
    private final JLabel status = new JLabel("Prêt — sélectionnez une requête dans Proxy ou Repeater.");
    private final JCheckBox automaticCapture = new JCheckBox("Capture automatique des requêtes locales", true);
    private final Set<String> sentFingerprints = ConcurrentHashMap.newKeySet();
    private Timer heartbeat;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("Security Center Connector");
        api.userInterface().registerContextMenuItemsProvider(new SecurityCenterMenu());
        api.proxy().registerResponseHandler(new AutomaticProxyCapture());
        api.userInterface().registerSuiteTab("Security Center", createSuiteTab());
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
        connection.add(automaticCapture);
        panel.add(connection, BorderLayout.NORTH);
        panel.add(status, BorderLayout.CENTER);
        return panel;
    }

    private final class AutomaticLocalCapture implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            String requestUrl = response.initiatingRequest().url();
            if (automaticCapture.isSelected() && isLocalUrl(requestUrl) && !isBackendUrl(requestUrl)) {
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
        if (!automaticCapture.isSelected() || !isLocalUrl(requestUrl) || isBackendUrl(requestUrl)) return;
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
        try {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(normalizedBackend() + "/api/v1/integrations/burp/heartbeat"))
                .header("X-Security-Center-Key", configuredApiKey())
                .POST(BodyPublishers.noBody())
                .build();
            httpClient.sendAsync(request, BodyHandlers.discarding()).exceptionally(error -> null);
        } catch (RuntimeException ignored) {
            // Le prochain heartbeat réessaiera après correction de l’URL ou redémarrage du backend.
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
        validateLocalUrl(request.url());
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

    private static void validateLocalUrl(String value) {
        URI uri = URI.create(value);
        String host = uri.getHost();
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Seules les URL HTTP/HTTPS sont acceptées.");
        }
        if (!Set.of("127.0.0.1", "localhost", "::1").contains(host)) {
            throw new IllegalArgumentException("Le connecteur MVP accepte uniquement les cibles locales.");
        }
    }

    private static boolean isLocalUrl(String value) {
        try {
            validateLocalUrl(value);
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
