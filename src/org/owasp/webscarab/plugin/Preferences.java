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
        // Properties work as follows :
        //    Read the defaults from the .jar.
        //    Then look for a props file in the user's home directory, and load it if it exists
        
        String sep = System.getProperty("file.separator");
        String props = "WebScarab.properties";
        String home = System.getProperty("user.home");

        InputStream is = null;
        
        Properties defaults = new Properties();
        is = ClassLoader.getSystemResourceAsStream(props);
        if (is == null) {
            System.err.println("No WebScarab.properties in the .jar!");
        } else {
            try {
                defaults.load(is);
            } catch (IOException ioe) {
                System.err.println("Error reading default properties file " + ioe);
            }
        }
        
        Properties homeProps = new Properties(defaults);
        try {
            is = new FileInputStream(home + sep + props);
            try {
                homeProps.load(is);
            } catch (IOException ioe) {
                System.err.println("IOError reading " + home + sep + props + " : " + ioe);
            }
        } catch (FileNotFoundException fnfe) {
            System.err.println("No user properties file found");
        }
        return homeProps;
    }
    
    public static void savePreferences() throws FileNotFoundException, IOException {
        String home = System.getProperty("user.home");
        String sep = System.getProperty("file.separator");
        String propfile = home + sep + "WebScarab.properties";
        
        if (_props == null) {
            System.err.println("savePreferences called on a null Properties");
            return;
        }
        FileOutputStream fos;
        fos = new FileOutputStream(propfile);
        _props.store(fos,"WebScarab Properties");
        fos.close();
    }
    
}
