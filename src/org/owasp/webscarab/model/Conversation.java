/*
 * Conversation.java
 *
 * Created on July 16, 2003, 7:11 PM
 */

package org.owasp.webscarab.model;

import java.util.Properties;

import java.net.URL;

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
    
    private Request _request;
    private Response _response;
    private NodeList _nodelist;
    private Properties _props;
    
    /** Creates a new instance of Conversation */
    public Conversation(Request request, Response response) {
        _request = request;
        _response = response;
        _props = new Properties();
        URL url = request.getURL();
        setProperty("METHOD", request.getMethod());
        setProperty("URL", URLUtil.schemeHostPortPath(url));
        String value = url.getQuery();
        if (value != null) {
            setProperty("QUERY", value);
        }
        value = request.getHeader("Cookie");
        if (value != null) {
            setProperty("COOKIE", value);
        }
        byte[] content = request.getContent();
        if (content != null && content.length>0) {
            setProperty("BODY", new String(content));
        }
        setProperty("STATUS", response.getStatusLine());
        value = response.getHeader("Set-Cookie");
        if (value != null) {
            setProperty("SET-COOKIE", value);
        }
        content = response.getContent();
        if (content != null && content.length>0) {
            setProperty("CHECKSUM",  checksum(content));
            setProperty("SIZE", Integer.toString(content.length));
        } else {
            setProperty("SIZE", "0");
        }
    }
    
    public Request getRequest() {
        return _request;
    }
    
    public Response getResponse() {
        return _response;
    }
    
    public void flush() {
        _request = null;
        _response = null;
        _nodelist = null;
    }
    
    public void setNodeList(NodeList nodelist) {
        _nodelist = nodelist;
    }
    
    public NodeList getNodeList() {
        return _nodelist;
    }
    
    public void setProperty(String key, String value) {
        _props.setProperty(key, value);
    }
    
    public String getProperty(String key) {
        return (String) _props.getProperty(key);
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
