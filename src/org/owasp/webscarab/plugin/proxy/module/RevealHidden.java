/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

import org.owasp.util.StringUtil;

import org.owasp.webscarab.model.*;
import org.owasp.webscarab.plugin.proxy.AbstractProxyPlugin;

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
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public RevealHidden() {
        _prop.put("RevealHidden.enabled","false");
        configure();
    }
    
    public void configure() {
        String prop = "RevealHidden.enabled";
        String value = _prop.get(prop);
        setEnabled("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
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
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "RevealHidden.enabled";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
    }
    
    private void setProperty(String prop, String value) {
        String previous = _prop.get(prop);
        if (previous == null || !previous.equals(value)) {
            _prop.put(prop,value);
        }
    }
    
    
}
