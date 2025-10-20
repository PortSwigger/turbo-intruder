package burp;

import burp.api.montoya.MontoyaApi;
import kotlin.Pair;
import kotlin.text.Charsets;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;

public class Utils {

    static boolean gotBurp = false;
    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    static MontoyaApi montoyaApi;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static WordRecorder witnessedWords = new WordRecorder();
    public static boolean unloaded = false;

    public static Utilities utilities;

    public static void setTurboSize(Dimension size) {
        callbacks.saveExtensionSetting("turboHeight", String.valueOf(size.height));
        callbacks.saveExtensionSetting("turboWidth", String.valueOf(size.width));
    }

    public static String bytesToString(byte[] bytes) {
        return new String(bytes, Charsets.ISO_8859_1);
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

    public static void setClipboard(String contents) {
        StringSelection selection = new StringSelection(contents);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
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


    public static byte[] h2request(IHttpService service, byte[] req) {
        return h2request(service, req, null);
    }

    // based on BulkScan.request()
    public static byte[] h2request(IHttpService service, byte[] req, String connectionID) {
        LinkedList<Pair<String, String>> h2headers = H2Connection.Companion.buildReq(new HTTP2Request(helpers.bytesToString(req)));
        ArrayList<IHttpHeader> headers = new ArrayList<>();
        for (Pair<String, String> header: h2headers) {
            headers.add(helpers.buildHeader(header.getFirst(), header.getSecond()));
        }
        //h2headers.forEach((key, value) -> { headers.add(helpers.buildHeader(key, value)); });
        byte[] body = getBodyBytes(req);
        byte[] responseBytes;
        try {

            if (connectionID == null) {
                responseBytes = callbacks.makeHttp2Request(service, headers, body, true);
            } else {
                responseBytes = callbacks.makeHttp2Request(service, headers, body, true, connectionID);
            }
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
        return indexOf(response, "\r\n\r\n".getBytes())+4;

//        int i = 0;
//        int newlines_seen = 0;
//        while (i < response.length) {
//            byte x = response[i];
//            if (x == '\n') {
//                newlines_seen++;
//            } else if (x != '\r') {
//                newlines_seen = 0;
//            }
//
//            if (newlines_seen == 2) {
//                break;
//            }
//            i += 1;
//        }

        // no idea why I did this!
//        while (i < response.length && (response[i] == ' ' || response[i] == '\n' || response[i] == '\r')) {
//            i++;
//        }

//        return i;
    }

    static public int indexOf(byte[] outerArray, byte[] smallerArray) {
        for(int i = 0; i < outerArray.length - smallerArray.length+1; ++i) {
            boolean found = true;
            for(int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i+j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    public static byte[] stringToBytes(String string) {
//        // todo look up actual charset from headers and use that
//        if (Utils.helpers != null) {
//            return Utils.helpers.stringToBytes(string);
//        }

        try {
            return string.getBytes(StandardCharsets.ISO_8859_1); // ISO_8859_1
        } catch (Exception e) {
            throw new RuntimeException("failed to convert string to bytes");
        }
    }

    private static void printBytes(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X ", b)); // Converts byte to hex
        }
        Utilities.out(hexString.toString().trim());
    }

}