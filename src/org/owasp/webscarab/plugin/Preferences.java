/*
 * Preferences.java
 *
 * Created on September 15, 2003, 7:19 AM
 */

package org.owasp.webscarab.plugin;

import java.util.Properties;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class Preferences {
    
    static Properties _props = null;
    
    /** Creates a new instance of Preferences */
    private Preferences() {
    }
    
    public static Properties getPreferences() {
        if (_props == null) {
            _props = readPreferences();
        }
        return _props;
    }
    
    private static Properties readPreferences() {
        // Look for a props file in the user's home directory, and load it if it exists
        
        String sep = System.getProperty("file.separator");
        String home = System.getProperty("user.home");
        String file = home + sep + "WebScarab.properties";

        InputStream is = null;
        
        Properties homeProps = new Properties();
        try {
            is = new FileInputStream(file);
            try {
                homeProps.load(is);
            } catch (IOException ioe) {
                System.err.println("IOError reading " + file + " : " + ioe);
            }
        } catch (FileNotFoundException fnfe) {
            System.err.println("user properties file " + file + " not found");
        }
        return homeProps;
    }
    
    public static void savePreferences() throws FileNotFoundException, IOException {
        String home = System.getProperty("user.home");
        String sep = System.getProperty("file.separator");
        String file = home + sep + "WebScarab.properties";
        
        if (_props == null) {
            System.err.println("savePreferences called on a null Properties");
            return;
        }
        FileOutputStream fos;
        fos = new FileOutputStream(file);
        _props.store(fos,"WebScarab Properties");
        fos.close();
    }
    
}
