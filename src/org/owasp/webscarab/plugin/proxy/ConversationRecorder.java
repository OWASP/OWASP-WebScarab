/*
 * ConversationRecorder.java
 *
 * Created on August 4, 2003, 10:31 AM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.io.InputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ConversationRecorder implements HTTPClient {

    private HTTPClient _client = null;
    private Request _request = null;
    private Response _response = null;
    
    /** Creates a new instance of ConversationRecorder */
    public ConversationRecorder(HTTPClient client) {
        _client = client;
    }
    
    public Response fetchResponse(Request request) {
        _request = request;
        _response = _client.fetchResponse(request);
        return _response;
    }
    
    public Request getRequest() {
        return _request;
    }
    
    public Response getResponse() {
        return _response;
    }

    public void reset() {
        _request = null;
        _response = null;
    }
}
