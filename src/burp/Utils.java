package burp;
import java.awt.*;
import java.io.PrintWriter;

public class Utils {

    static boolean gotBurp = false;
    static IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static WordRecorder witnessedWords = new WordRecorder();
    public static boolean unloaded = false;

    public static void setTurboSize(Dimension size) {
        callbacks.saveExtensionSetting("turboHeight", String.valueOf(size.height));
        callbacks.saveExtensionSetting("turboWidth", String.valueOf(size.width));
    }

    public static Dimension getTurboSize() {
        try {
            int height = Integer.parseInt(callbacks.loadExtensionSetting("turboHeight"));
            int width = Integer.parseInt(callbacks.loadExtensionSetting("turboWidth"));
            return new Dimension(width, height);
        } catch(Exception e) {
            return new Dimension(1280, 800);
        }
    }

    static void setBurpPresent(IBurpExtenderCallbacks incallbacks) {
        gotBurp = true;
        callbacks = incallbacks;
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

}
