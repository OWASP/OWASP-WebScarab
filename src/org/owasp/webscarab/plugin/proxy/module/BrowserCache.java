/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

// import org.owasp.util.StringUtil;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
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
public class BrowserCache extends AbstractProxyPlugin {
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public BrowserCache() {
        _prop.put("BrowserCache.enabled","false");
        configure();
    }
    
    public void configure() {
        String prop = "BrowserCache.enabled";
        String value = _prop.getProperty(prop);
        setEnabled("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Browser Cache");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "BrowserCache.enabled";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
    }
    
    private void setProperty(String prop, String value) {
        String previous = _prop.getProperty(prop);
        if (previous == null || !previous.equals(value)) {
            _prop.put(prop,value);
        }
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new ProxyPlugin(in);
    }    
    
    private class ProxyPlugin implements HTTPClient {
    
        private HTTPClient _in;
        
        public ProxyPlugin(HTTPClient in) {
            _in = in;
        }
        
        public Response fetchResponse(Request request) {
            if (_enabled) {
                request.deleteHeader("ETag");
                request.deleteHeader("If-Modified-Since");
            }
            return _in.fetchResponse(request);
        }
        
    }
    
}
