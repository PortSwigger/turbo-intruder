package burp;
import kotlin.Pair;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;

public class Utils {

    static boolean gotBurp = false;
    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static WordRecorder witnessedWords = new WordRecorder();
    public static boolean unloaded = false;

    public static void setTurboSize(Dimension size) {
        callbacks.saveExtensionSetting("turboHeight", String.valueOf(size.height));
        callbacks.saveExtensionSetting("turboWidth", String.valueOf(size.width));
    }

    public static ArrayList<String> getClipboard() {
        String clipboard = "";
        try {
            clipboard = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
        } catch(Exception e) {
            err("failed to read from clipboard");
        }
        return new ArrayList<>(Arrays.asList(clipboard.split("\\r?\\n")));
    }

    public static Dimension getTurboSize() {
        try {
            int height = Integer.parseInt(callbacks.loadExtensionSetting("turboHeight"))-20; // don't ask
            int width = Integer.parseInt(callbacks.loadExtensionSetting("turboWidth"));
            return new Dimension(width, height);
        } catch(Exception e) {
            return new Dimension(1280, 800);
        }
    }

    static void setBurpPresent(IBurpExtenderCallbacks incallbacks) {
        gotBurp = true;
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    static void out(String message) {
        if (gotBurp) {
            stdout.println(message);
        }
        else {
            System.out.println(message);
        }

    }
    static void err(String message) {
        if (gotBurp) {
            stderr.println(message);
        }
        else {
            System.out.println(message);
        }
    }

    static String getHeaders(String request) {
        int bodyStart = request.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            return request;
        }
        return request.substring(0, bodyStart);
    }

    // based on BulkScan.request()
    public static byte[] h2request(IHttpService service, byte[] req) {
        LinkedList<Pair<String, String>> h2headers = Connection.Companion.buildReq(new HTTP2Request(helpers.bytesToString(req)));
        ArrayList<IHttpHeader> headers = new ArrayList<>();
        for (Pair<String, String> header: h2headers) {
            headers.add(helpers.buildHeader(header.getFirst(), header.getSecond()));
        }
        //h2headers.forEach((key, value) -> { headers.add(helpers.buildHeader(key, value)); });
        byte[] body = getBodyBytes(req);
        byte[] responseBytes;
        try {
            responseBytes = callbacks.makeHttp2Request(service, headers, body, true);
        } catch (RuntimeException e) {
            responseBytes = null;
        }
        return responseBytes;
    }

    static byte[] getBodyBytes(byte[] response) {
        if (response == null) { return null; }
        int bodyStart = getBodyStart(response);
        return Arrays.copyOfRange(response, bodyStart, response.length);
    }

    public static int getBodyStart(byte[] response) {
        int i = 0;
        int newlines_seen = 0;
        while (i < response.length) {
            byte x = response[i];
            if (x == '\n') {
                newlines_seen++;
            } else if (x != '\r') {
                newlines_seen = 0;
            }

            if (newlines_seen == 2) {
                break;
            }
            i += 1;
        }


        while (i < response.length && (response[i] == ' ' || response[i] == '\n' || response[i] == '\r')) {
            i++;
        }

        return i;
    }

}
