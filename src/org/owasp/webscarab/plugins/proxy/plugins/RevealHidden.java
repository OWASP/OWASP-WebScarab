/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugins.proxy.plugins;

import org.owasp.webscarab.model.*;
import org.owasp.webscarab.plugins.proxy.AbstractProxyPlugin;

import java.util.Properties;
import java.util.Enumeration;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class RevealHidden extends AbstractProxyPlugin {
    
    private Properties _props = new Properties();
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public RevealHidden() {
        _props.setProperty("RevealHidden.enabled","false");
        configure();
    }
    
    private void configure() {
        String prop = "RevealHidden.enabled";
        String value = _props.getProperty(prop);
        if (value == null) value = "";
        setEnabled(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Reveal Hidden");
    }
    
    public Request interceptRequest(Request request) {
        return request;
    }
    
    public Response interceptResponse(Request request, Response response) throws IOException {
        if (_enabled) {
            String ct = response.getHeader("Content-Type");
            if (ct != null && ct.matches("text/.*")) {
                InputStream is = response.getContentStream();
                if (is != null) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[2048];
                    int read = is.read(buf);
                    while (read > 0) {
                        baos.write(buf,0,read);
                        read = is.read(buf);
                    }
                    response.setContent(baos.toByteArray());
                    response.setContentStream(null);
                }
                byte[] content = response.getContent();
                if (content != null) {
                    response.setContent(revealHidden(content));
                }
            }
        }
        return response;
    }
    
    private byte[] revealHidden(byte[] content) {
        String text = new String(content);
        text = text.replaceAll("type=\"[Hh][Ii][Dd][Dd][Ee][Nn]\"", "  type=\"text\"");
        text = text.replaceAll("type='[Hh][Ii][Dd][Dd][Ee][Nn]'", "  type='text'");
        text = text.replaceAll("type=[Hh][Ii][Dd][Dd][Ee][Nn]", "  type=text");
        return text.getBytes();
    }
    
    public void setProperties(Properties properties) {
        // This just allows us to copy our defaults over into
        // the main properties class, if they are not set already
        Enumeration propnames = _props.keys();
        while (propnames.hasMoreElements()) {
            String key = (String) propnames.nextElement();
            String value = properties.getProperty(key);
            if (value == null) {
                properties.setProperty(key,_props.getProperty(key));
            }
        }
        _props = properties;
        // Now perform plugin-specific configuration
        configure();
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "RevealHidden.enabled";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
    }
    
    private void setProperty(String prop, String value) {
        String previous = _props.getProperty(prop);
        if (previous == null || !previous.equals(value)) {
            _props.setProperty(prop,value);
        }
    }
    
    
}
