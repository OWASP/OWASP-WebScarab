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
    
    static Properties _props = new Properties();
    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.model.Preferences");
    private static String _location = null;
    
    /** Creates a new instance of Preferences */
    private Preferences() {
    }
    
    public static Properties getPreferences() {
        return _props;
    }
    
    public static void loadPreferences(String file) throws IOException {
        // If we are given a filename to load, use it, otherwise
        // look for a props file in the user's home directory
        // if the file does not exist, use the standard defaults
        
        if (file == null) {
            String sep = System.getProperty("file.separator");
            String home = System.getProperty("user.home");
            _location = home + sep + "WebScarab.properties";
        } else {
            _location = file;
        }
        
        try {
            Properties props = new Properties();
            InputStream is = new FileInputStream(_location);
            props.load(is);
            _props = props;
        } catch (FileNotFoundException fnfe) {
            // we'll just use the defaults
        }
    }
    
    public static void savePreferences() throws IOException {
        FileOutputStream fos = new FileOutputStream(_location);
        _props.store(fos,"WebScarab Properties");
        fos.close();
    }
    
    public static void setPreference(String key, String value) {
        _props.setProperty(key, value);
    }
    
    public static String getPreference(String key) {
        return _props.getProperty(key);
    }
    
    public static String getPreference(String key, String defaultValue) {
        return _props.getProperty(key, defaultValue);
    }
    
    public static String remove(String key) {
        return (String) _props.remove(key);
    }
    
}
