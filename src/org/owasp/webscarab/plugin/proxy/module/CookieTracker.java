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
import org.owasp.webscarab.model.CookieJar;
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
public class CookieTracker extends AbstractProxyPlugin {
    
    private boolean _enabled = false;
    private CookieJar _cookieJar;
    
    /** Creates a new instance of RevealHidden */
    public CookieTracker(CookieJar cookieJar) {
        _cookieJar = cookieJar;
        setDefaultProperty("CookieTracker.enabled","true");
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "CookieTracker.enabled";
        String value = _prop.getProperty(prop);
        setEnabled("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Cookie Tracker");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "CookieTracker.enabled";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
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
                // FIXME we should do something about any existing cookies that are in the Request
                // they could have been set via JavaScript, or some such!
                _cookieJar.addRequestCookies(request);
            }
            Response response = _in.fetchResponse(request);
            if (_enabled) {
                _cookieJar.updateCookies(response);
            }
            return response;
        }
        
    }
    
}
