/*
 * Preferences.java
 *
 * Created on September 15, 2003, 7:19 AM
 */

package org.owasp.webscarab.model;

import java.util.Properties;
import java.util.logging.Logger;

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
    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.model.Preferences");
    
    /** Creates a new instance of Preferences */
    private Preferences() {
    }
    
    public static Properties getPreferences() {
        if (_props == null) {
            _logger.severe("getPreferences called, but not yet loaded!");
            System.exit(1);
        }
        return _props;
    }
    
    public static void loadPreferences() throws IOException {
        // Look for a props file in the user's home directory, and load it if it exists
        // otherwise loads the default props distributed in the jar
        
        String sep = System.getProperty("file.separator");
        String home = System.getProperty("user.home");
        String file = home + sep + "WebScarab.properties";

        try {
            Properties props = new Properties();
            InputStream is = new FileInputStream(file);
            props.load(is);
            _props = props;
        } catch (FileNotFoundException fnfe) {
            Properties props = new Properties();
            InputStream is = props.getClass().getResourceAsStream("/WebScarab.properties");
            props.load(is);
            _props = props;
        }
    }
    
    public static void savePreferences() throws FileNotFoundException, IOException {
        String sep = System.getProperty("file.separator");
        String home = System.getProperty("user.home");
        String file = home + sep + "WebScarab.properties";
        
        if (_props == null) {
            System.err.println("savePreferences called on a null Properties");
            return;
        }
        FileOutputStream fos = new FileOutputStream(file);
        _props.store(fos,"WebScarab Properties");
        fos.close();
    }
    
}
