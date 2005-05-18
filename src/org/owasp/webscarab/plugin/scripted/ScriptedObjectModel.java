/*
 * ScriptedObjectModel.java
 *
 * Created on 02 February 2005, 06:32
 */

package org.owasp.webscarab.plugin.scripted;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.Framework;

import java.io.IOException;
import java.net.MalformedURLException;

/**
 * Provides a wrapper around the Scripting plugin, so that we do not expose
 * potentially dangerous methods, such as adding listeners, stopping the plugin, etc
 * @author rogan
 */
public class ScriptedObjectModel {
    
    private Framework _framework;
    private FrameworkModel _model;
    private Scripted _scripted;
    
    /**
     * Creates a new instance of ScriptedObjectModel
     * @param framework The framework that holds WebScarab together
     * @param scripted the scripting plugin that we interact with
     */
    public ScriptedObjectModel(Framework framework, Scripted scripted) {
        _framework = framework;
        _model = _framework.getModel();
        _scripted = scripted;
    }
    
    /**
     * adds a conversation to the overall WebScarab framework.
     * All such conversations will be processed by all of the other plugins, and will be
     * available for later review.
     * The Response includes the corresponding Request as a parameter.
     * @param response the Response to add to the framework
     * @return the ConversationID allocated to the conversation
     */    
    public ConversationID addConversation(Response response) {
        return _framework.addConversation(response.getRequest(), response, "Scripted");
    }
    
    /**
     * convenience method, saving the user from doing "new ConversationID(1)" each time
     * returns a copy of the desired Request, or null if the id did not exist
     * @param id the numerical id of the request
     * @return a copy of the desired Request, or null if it did not exist
     */    
    public Request getRequest(int id) {
        return getRequest(new ConversationID(id));
    }
    
    public Request getRequest(ConversationID id) {
        Request request = _model.getRequest(id);
        if (request == null) return request;
        return new Request(request);
    }
    
    public Response getResponse(int id) {
        return getResponse(new ConversationID(id));
    }
    
    public Response getResponse(ConversationID id) {
        Response response = _model.getResponse(id);
        if (response == null) return response;
        return new Response(response);
    }
    
    public int getChildCount(String url) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlModel().getChildCount(myUrl);
    }
    
    public HttpUrl getChildAt(String url, int index) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlModel().getChildAt(myUrl, index);
    }
    
    public String getUrlProperty(String url, String property) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlProperty(myUrl, property);
    }
    
    public int getConversationCount(String url) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getConversationModel().getConversationCount(myUrl);
    }
    
    public ConversationID getConversationAt(String url, int index) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getConversationModel().getConversationAt(myUrl, index);
    }
    
    public String getConversationProperty(int id, String property) {
        return getConversationProperty(new ConversationID(id), property);
    }
    
    public String getConversationProperty(ConversationID id, String property) {
        return _model.getConversationProperty(id, property);
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
