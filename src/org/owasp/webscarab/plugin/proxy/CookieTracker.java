/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.util.Date;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;

/**
 *
 * @author  rdawes
 */
public class CookieTracker extends ProxyPlugin {
    
    private SiteModel _model = null;
    
    private boolean _injectRequests = false;
    private boolean _readResponses = false;
    
    /** Creates a new instance of RevealHidden */
    public CookieTracker() {
        parseProperties();
    }
    
    public void setModel(SiteModel model, String type, Object connection) {
        _model = model;
    }
    
    public void parseProperties() {
        String prop = "CookieTracker.injectRequests";
        String value = Preferences.getPreference(prop, "false");
        _injectRequests = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
        prop = "CookieTracker.readResponses";
        value = Preferences.getPreference(prop, "true");
        _readResponses = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Cookie Tracker");
    }
    
    public void setInjectRequests(boolean bool) {
        _injectRequests = bool;
        String prop = "CookieTracker.injectRequests";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }

    public boolean getInjectRequests() {
        return _injectRequests;
    }
    
    public void setReadResponses(boolean bool) {
        _readResponses = bool;
        String prop = "CookieTracker.readResponses";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }

    public boolean getReadResponses() {
        return _readResponses;
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
            if (_injectRequests) {
                // FIXME we should do something about any existing cookies that are in the Request
                // they could have been set via JavaScript, or some such!
                Cookie[] cookies = _model.getCookiesForUrl(request.getURL());
                if (cookies.length>0) {
                    StringBuffer buff = new StringBuffer();
                    buff.append(cookies[0].getName()).append("=").append(cookies[0].getValue());
                    for (int i=1; i<cookies.length; i++) {
                        buff.append("; ").append(cookies[i].getName()).append("=").append(cookies[i].getValue());
                    }
                    request.setHeader("Cookie", buff.toString());
                }
            }
            Response response = _in.fetchResponse(request);
            if (_readResponses && response != null) {
                String[][] headers = response.getHeaders();
                for (int i=0; i<headers.length; i++) {
                    if (headers[i][0].equals("Set-Cookie") || headers[i][0].equals("Set-Cookie2")) {
                        Cookie cookie = new Cookie(new Date(), request.getURL(), headers[i][1]);
                        _model.addCookie(cookie);
                    }
                }
            }
            return response;
        }
        
    }
    
}
