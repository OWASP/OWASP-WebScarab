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
    
    /**
     * returns a copy of the desired Request, or null if the id did not exist
     * @param id the numerical id of the request
     * @return a copy of the desired Request, or null if it did not exist
     */    
    public Request getRequest(ConversationID id) {
        Request request = _model.getRequest(id);
        if (request == null) return request;
        return new Request(request);
    }
    
    /**
     * convenience method, saving the user from doing "new ConversationID(1)" each time
     * returns a copy of the desired Response, or null if the id did not exist
     * @param id the numerical id of the response
     * @return a copy of the desired Response, or null if it did not exist
     */    
    public Response getResponse(int id) {
        return getResponse(new ConversationID(id));
    }
    
    /**
     * returns a copy of the desired Response, or null if the id did not exist
     * @param id the numerical id of the response
     * @return a copy of the desired Response, or null if it did not exist
     */    
    public Response getResponse(ConversationID id) {
        Response response = _model.getResponse(id);
        if (response == null) return response;
        return new Response(response);
    }
    
    /**
     * returns the number of URLs under the supplied URL
     * @param url the url
     * @throws MalformedURLException if the url is malformed
     * @return the number of child URLs
     */    
    public int getChildCount(String url) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlModel().getChildCount(myUrl);
    }
    
    /**
     * returns the indicated child of the supplied URL
     * @param url the parent url
     * @param index the index of the desired child
     * @throws MalformedURLException if the url is malformed
     * @return the url of the indicated child
     */    
    public HttpUrl getChildAt(String url, int index) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlModel().getChildAt(myUrl, index);
    }
    
    /**
     *
     * @param url
     * @param property
     * @throws MalformedURLException
     * @return
     */    
    public String getUrlProperty(String url, String property) throws MalformedURLException {
        HttpUrl myUrl = null;
        if (url != null) myUrl = new HttpUrl(url);
        return _model.getUrlProperty(myUrl, property);
    }
    
    /**
     * returns the number of conversations for the specified URL.
     * @throws MalformedURLException if the URL is malformed
     * @return the number of conversations 
     */    
    public int getConversationCount() {
        return _model.getConversationModel().getConversationCount();
    }
    
    /**
     * returns the identifier of the conversation at the specified index
     * @param index
     * @return the ConversationID at the requested index
     */    
    public ConversationID getConversationAt(int index) {
        return _model.getConversationModel().getConversationAt(index);
    }
    
    /**
     *
     * @param id
     * @param property
     * @return
     */    
    public String getConversationProperty(int id, String property) {
        return getConversationProperty(new ConversationID(id), property);
    }
    
    /**
     *
     * @param id
     * @param property
     * @return
     */    
    public String getConversationProperty(ConversationID id, String property) {
        return _model.getConversationProperty(id, property);
    }
    /**
     * instructs WebScarab to submit the supplied Request to the appropriate server, 
     * and return the corresponding corresponding Response to the caller
     * @param request the Request to execute
     * @throws IOException if there is any connectivity problem
     * @return the Response received from the server
     */    
    public Response fetchResponse(Request request) throws IOException {
        return _scripted.fetchResponse(request);
    }
    
    /**
     * checks whether the Scripted plugin can accept any more Requests for 
     * asynchronous fetching
     * @return true if at least one more Request can be submitted
     */    
    public boolean hasAsyncCapacity() {
        return _scripted.hasAsyncCapacity();
    }
    
    /**
     * instructs the Scripted plugin to fetch the supplied Request asynchronously
     * returns immediately without waiting for the Response
     * @param request the Request to execute
     */    
    public void submitAsyncRequest(Request request) {
        _scripted.submitAsyncRequest(request);
    }
    
    /**
     * checks whether the Scripted plugin is still busy fetching Requests
     * @return true if there are still pending Requests, false otherwise
     */    
    public boolean isAsyncBusy() {
        return _scripted.isAsyncBusy();
    }
    
    /**
     * checks whether the Scripted plugin has a Response ready
     * @return true if an asynchronous Request has completed, and the Response is ready
     */    
    public boolean hasAsyncResponse() {
        return _scripted.hasAsyncResponse();
    }
    
    /**
     * gets an asynchronous Response that corresponds to a previous Request
     * The actual Request can be obtained using the Response.getRequest() method
     * @throws IOException if there was any problem fetching the Response
     * @return a Response that was fetched
     */    
    public Response getAsyncResponse() throws IOException {
        return _scripted.getAsyncResponse();
    }
    
}
