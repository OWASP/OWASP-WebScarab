/*
 * ScriptedObjectModel.java
 *
 * Created on 02 February 2005, 06:32
 */

package org.owasp.webscarab.plugin.scripted;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.Framework;

import java.io.IOException;

/**
 *
 * @author  rogan
 */
public class ScriptedObjectModel {
    
    private Framework _framework;
    private SiteModel _model;
    private Scripted _scripted;
    
    /** Creates a new instance of ScriptedObjectModel */
    public ScriptedObjectModel(Framework framework, Scripted scripted) {
        _framework = framework;
        _model = _framework.getModel();
        _scripted = scripted;
    }
    
    public ConversationID addConversation(Response response) {
        return _framework.addConversation(response.getRequest(), response, "Scripted");
    }
    
    public Request getRequest(int id) {
        Request request = _model.getRequest(new ConversationID(id));
        if (request == null) return request;
        return new Request(request);
    }
    
    public Response fetchResponse(Request request) throws IOException {
        return _scripted.fetchResponse(request);
    }
    
    public boolean hasAsyncCapacity() {
        return _scripted.hasAsyncCapacity();
    }
    
    public void submitAsyncRequest(Request request) {
        _scripted.submitAsyncRequest(request);
    }
    
    public boolean isAsyncBusy() {
        return _scripted.isAsyncBusy();
    }
    
    public boolean hasAsyncResponse() {
        return _scripted.hasAsyncResponse();
    }
    
    public Response getAsyncResponse() throws IOException {
        return _scripted.getAsyncResponse();
    }
    
}
