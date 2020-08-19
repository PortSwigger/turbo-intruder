package burp;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ReadFromJar {
    public ArrayList<String> getFiles(String folder) throws IOException {
        ArrayList<String> fileNames = new ArrayList<>();
        final String path = folder;
        final File jarFile = new File(getClass().getProtectionDomain().getCodeSource().getLocation().getPath());
        final JarFile jar = new JarFile(jarFile);
        final Enumeration<JarEntry> entries = jar.entries(); //gives ALL entries in jar
        while(entries.hasMoreElements()) {
            final String name = entries.nextElement().getName();
            if (name.startsWith(path + "/")) {
                fileNames.add(name);
            }
        }
        jar.close();
        return fileNames;
    }
}
