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
    
    private boolean _injectRequests = false;
    private boolean _readResponses = false;
    private CookieJar _cookieJar;
    
    /** Creates a new instance of RevealHidden */
    public CookieTracker(CookieJar cookieJar) {
        _cookieJar = cookieJar;
        setDefaultProperty("CookieTracker.injectRequests","true");
        setDefaultProperty("CookieTracker.readResponses","true");
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "CookieTracker.injectRequests";
        String value = _prop.getProperty(prop);
        setInjectRequests("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
        prop = "CookieTracker.readResponses";
        value = _prop.getProperty(prop);
        setReadResponses("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Cookie Tracker");
    }
    
    public void setInjectRequests(boolean bool) {
        _injectRequests = bool;
        String prop = "CookieTracker.injectRequests";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getInjectRequests() {
        return _injectRequests;
    }
    
    public void setReadResponses(boolean bool) {
        _readResponses = bool;
        String prop = "CookieTracker.readResponses";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getReadResponses() {
        return _readResponses;
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
            if (_injectRequests) {
                // FIXME we should do something about any existing cookies that are in the Request
                // they could have been set via JavaScript, or some such!
                _cookieJar.addRequestCookies(request);
            }
            Response response = _in.fetchResponse(request);
            if (_readResponses && response != null) {
                _cookieJar.updateCookies(response);
            }
            return response;
        }
        
    }
    
}
