/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy;

// import org.owasp.util.StringUtil;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.proxy.ProxyPlugin;

import java.util.Properties;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class RevealHidden extends ProxyPlugin {
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public RevealHidden(Properties props) {
        super(props);
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "RevealHidden.enabled";
        String value = _props.getProperty(prop, "false");
        _enabled = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Reveal Hidden");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "RevealHidden.enabled";
        _props.setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new Plugin(in);
    }    
    
    private class Plugin implements HTTPClient {
    
        private HTTPClient _in;
        
        public Plugin(HTTPClient in) {
            _in = in;
        }
        
        public Response fetchResponse(Request request) throws IOException {
            Response response = _in.fetchResponse(request);
            if (_enabled) {
                String ct = response.getHeader("Content-Type");
                if (ct != null && ct.matches("text/.*")) {
                    byte[] content = response.getContent();
                    if (content != null) {
                        response.setContent(revealHidden(content));
                        response.addHeader("X-RevealHidden", "possibly modified");
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

    }
    
}
