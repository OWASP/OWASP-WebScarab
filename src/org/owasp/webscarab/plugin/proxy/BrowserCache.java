/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public class BrowserCache extends ProxyPlugin {
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public BrowserCache() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "BrowserCache.enabled";
        String value = Preferences.getPreference(prop, "false");
        _enabled = "true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value );
    }
    
    public String getPluginName() {
        return new String("Browser Cache");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "BrowserCache.enabled";
        Preferences.setPreference(prop,Boolean.toString(bool));
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
            if (_enabled) {
                // we could be smarter about this, and keep a record of the pages that we 
                // have seen so far, and only remove headers for those that we have not?
                request.deleteHeader("ETag");
                request.deleteHeader("If-Modified-Since");
                request.deleteHeader("If-None-Match");
            }
            return _in.fetchResponse(request);
        }
        
    }
    
}
