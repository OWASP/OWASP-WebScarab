/*
 * Conversation.java
 *
 * Created on July 16, 2003, 7:11 PM
 */

package org.owasp.webscarab.model;

import org.owasp.util.Prop;

import java.net.URL;
import java.util.Set;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.owasp.util.Convert;
import org.owasp.util.URLUtil;

import org.htmlparser.util.NodeList;

/**
 *
 * @author  rdawes
 */
public class Conversation {
    
    private Prop _props;
    
    /** Creates a new instance of Conversation */
    public Conversation() {
        _props = new Prop();
    }
    
    public Conversation(Request request, Response response) {
        _props = new Prop();
        String value;
        if (request != null) {
            setProperty("METHOD", request.getMethod());
            URL url = request.getURL();
            if (url != null) {
                setProperty("URL", URLUtil.schemeAuthPath(url));
                value = url.getQuery();
                if (value != null) {
                    setProperty("QUERY", value);
                }
            }
            value = request.getHeader("Cookie");
            if (value != null) {
                setProperty("COOKIE", value);
            }
            byte[] content = request.getContent();
            if (content != null && content.length>0) {
                setProperty("BODY", new String(content));
            }
        }
        if (response != null) {
            setProperty("STATUS", response.getStatusLine());
            value = response.getHeader("Set-Cookie");
            if (value != null) {
                setProperty("SET-COOKIE", value);
            }
            byte[] content = response.getContent();
            if (content != null && content.length>0) {
                setProperty("CHECKSUM", checksum(content));
                setProperty("SIZE", Integer.toString(content.length));
            } else {
                setProperty("SIZE", "0");
            }
        }
    }
    
    public void setProperty(String key, String value) {
        _props.put(key, value);
    }
    
    public String getProperty(String key) {
        return (String) _props.get(key);
    }
    
    public Set keySet() {
        return _props.keySet();
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

    public String[] getPropertyAsArray(String key) {
        String value = getProperty(key);
        if (value == null || value.length() == 0) {
            return null;
        }
        return value.split(", *");
    }

    private static String checksum(byte[] content) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            System.err.println("Can't calculate MD5 sums! No such algorithm!");
            System.exit(1);
        }
        return Convert.toHexString(md.digest(content));
    }
    
}
