/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

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
            Properties props = new Properties(System.getProperties());
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
