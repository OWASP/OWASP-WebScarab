/*
 * URLModel.java
 *
 * Created on July 25, 2003, 10:29 PM
 */

package org.owasp.webscarab.model;

import java.util.Properties;

/**
 *
 * @author  rdawes
 */
public class URLInfo {

    private Properties _props = new Properties();
    private String _url;
    
    /** Creates a new instance of URLModel */
    public URLInfo(String url) {
        _url = url;
    }
    
    public String getURL() {
        return _url;
    }
    
    public void setProperty(String key, String value) {
        _props.setProperty(key, value);
    }
    
    public String getProperty(String key) {
        return (String) _props.getProperty(key);
    }
    
    // also need to implement a reader and a writer (to a FileInput/OutputStream) ?
}
