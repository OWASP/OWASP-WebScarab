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
        System.out.println("Created a ConversationRecorder");
        _client = client;
    }
    
    public Response fetchResponse(Request request) {
        _request = new Request(request);
        _response = null;
        InputStream is = request.getContentStream();
        CopyInputStream cis = null;
        if (is != null) {
            cis = new CopyInputStream(is);
            request.setContentStream(cis);
            _request.setContentStream(cis);
        }
        Response response = _client.fetchResponse(request);
        _response = new Response(response);
        is = response.getContentStream();
        cis = null;
        if (is != null) {
            cis = new CopyInputStream(is);
            response.setContentStream(cis);
            _response.setContentStream(cis);
        }
        return response;
    }
    
    public Request getRequest() {
        if (_request != null) {
            InputStream is = _request.getContentStream();
            if (is != null && is instanceof CopyInputStream) {
                _request.setContent(((CopyInputStream) is).toByteArray());
                _request.setContentStream(null);
            }
        }
        return _request;
    }
    
    public Response getResponse() {
        if (_response != null) {
            InputStream is = _response.getContentStream();
            if (is != null && is instanceof CopyInputStream) {
                try {
                    if (is.available()>0) {
                        while (is.read() > 0);
                    }
                } catch (IOException ioe) {
                    System.out.println("Error flushing the conversation : " + ioe);
                }
                _response.setContent(((CopyInputStream) is).toByteArray());
                _response.setContentStream(null);
            }
        }
        return _response;
    }

}
