/*
 * URLModel.java
 *
 * Created on July 25, 2003, 10:29 PM
 */

package org.owasp.webscarab.model;

import org.owasp.util.Prop;
import java.util.Set;

/**
 *
 * @author  rdawes
 */
public class URLInfo {

    private Prop _props = new Prop();
    private String _url;
    
    /** Creates a new instance of URLModel */
    public URLInfo(String url) {
        _url = url;
    }
    
    public String getURL() {
        return _url;
    }
    
    public void setProperty(String key, String value) {
        _props.put(key, value);
    }
    
    public String getProperty(String key) {
        return _props.get(key);
    }
    
    public Set keySet() {
        return _props.keySet();
    }
    
    public String toString() {
        return _url;
    }
    
}
