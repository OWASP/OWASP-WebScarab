package org.owasp.webscarab.plugin.manualrequest;

/*
 * $Id: ManualRequest.java,v 1.6 2004/03/18 08:13:20 rogan Exp $
 */

import org.owasp.webscarab.httpclient.URLFetcher;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.CookieJar;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

public class ManualRequest extends AbstractWebScarabPlugin {
    
    private Plug _plug = null;
    private CookieJar _cookieJar = null;
    private Response _response = null;
    
    public ManualRequest(Plug plug) {
        
        _plug = plug;
        _cookieJar = plug.getCookieJar();
        
        System.err.println("ManualRequest initialised");
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Manual Request");
    }
    
    public Response fetchResponse(Request request) {
        if (request != null) {
            URLFetcher uf = new URLFetcher();
            _response = uf.fetchResponse(request);
            if (_response != null) {
                _plug.addConversation("Manual Request", request, _response);
                return _response;
            }
        }
        System.err.println("null request or response");
        return null;
    }
    
    public void addRequestCookies(Request request) {
        _cookieJar.addRequestCookies(request);
    }
    
    public void updateCookies() {
        if (_response != null) {
            _cookieJar.updateCookies(_response);
        }
    }
    
}
