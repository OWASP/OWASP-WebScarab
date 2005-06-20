/*
 * ScriptableConversation.java
 *
 * Created on 20 June 2005, 09:03
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public class ScriptableConversation {
    
    private Request _request;
    private Response _response;
    private String _origin;
    
    private boolean _cancelled = false;
    private boolean _analyse = true;
    
    /** Creates a new instance of ScriptableConversation */
    public ScriptableConversation(Request request, Response response, String origin) {
        _request = request;
        _response = response;
        _origin = origin;
    }
    
    public Request getRequest() {
        return new Request(_request); // protective copy
    }
    
    public Response getResponse() {
        return new Response(_response); // protective copy
    }
    
    public String getOrigin() {
        return _origin;
    }
    
    public void setCancelled(boolean cancelled) {
        _cancelled = cancelled;
    }
    
    public boolean isCancelled() {
        return _cancelled;
    }
    
    public void setAnalyse(boolean analyse) {
        _analyse = analyse;
    }
    
    public boolean shouldAnalyse() {
        return _analyse;
    }
    
}
