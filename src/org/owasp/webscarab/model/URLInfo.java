/*
 * URLModel.java
 *
 * Created on July 25, 2003, 10:29 PM
 */

package org.owasp.webscarab.model;

import java.util.Properties;
import java.util.Set;

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
    
    public Set keySet() {
        return _props.keySet();
    }
    
    public String toString() {
        return _url;
    }
    
    public void setProperty(String key, String value) {
        synchronized (_props) {
            String previous = getProperty(key);
            if (value != null && (previous == null || !value.equals(previous))) {
                _props.setProperty(key,value);
            } else if (value == null) {
                _props.remove(key);
            }
        }
    }
    
    public void addProperty(String key, String value) {
        synchronized (_props) {
            String current = getProperty(key);
            if (current == null) {
                setProperty(key, value);
            } else {
                int pos = current.indexOf(value);
                if ( pos == -1 ) {
                    setProperty(key,current + ", " + value);
                } else {
                    boolean present = false;
                    while (pos > -1 && !present) {
                        if (pos + value.length() == current.length() || current.substring(pos+value.length(),pos+value.length()+1).equals(",")) {
                            present = true;
                        }
                        pos = current.indexOf(value,pos+1);
                    }
                    if (!present) {
                        setProperty(key,current + ", " + value);
                    }
                }
            }
        }
    }
    
    public void setProperty(String key, Boolean value) {
        if (value == null) {
            setProperty(key, (String) null);
        } else if (value == Boolean.FALSE) {
            setProperty(key, "false");
        } else {
            setProperty(key, "true");
        }
    }
    
    public void setProperty(String key, String[] values) {
        String value = null;
        if (values != null && values.length > 0) {
            value = new String(values[0]);
            for (int i=1; i<values.length; i++) {
                value = value.concat(", " + values[i]);
            }
        }
        setProperty(key,value);
    }
    
    public String getProperty(String key) {
        synchronized (_props) {
            return _props.getProperty(key);
        }
    }
    
    public Boolean getPropertyAsBoolean(String key) {
        String value = getProperty(key);
        if (value == null) {
            return null;
        } else if (value.equalsIgnoreCase("true")) {
            return Boolean.TRUE;
        } else if (value.equalsIgnoreCase("false")) {
            return Boolean.FALSE;
        }
        return null;
    }
    
    public String[] getPropertyAsArray(String key) {
        String value = getProperty(key);
        if (value == null || value.length() == 0) {
            return null;
        }
        return value.split(", *");
    }
}
