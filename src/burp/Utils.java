package burp;
import java.io.PrintWriter;

public class Utils {

    static boolean gotBurp = false;
    static IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static WordRecorder witnessedWords = new WordRecorder();
    public static boolean unloaded = false;

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

}
