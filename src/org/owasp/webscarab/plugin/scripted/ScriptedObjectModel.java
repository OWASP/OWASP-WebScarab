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

/**
 *
 * @author  rogan
 */
public class ScriptedObjectModel {
    
    private Framework _framework;
    private SiteModel _model;
    
    /** Creates a new instance of ScriptedObjectModel */
    public ScriptedObjectModel(Framework framework) {
        _framework = framework;
        _model = _framework.getModel();
    }
    
    public ConversationID addConversation(Request request, Response response) {
        return _framework.addConversation(request, response, "Scripted");
    }
    
    public Request getRequest(int id) {
        Request request = _model.getRequest(new ConversationID(id));
        if (request == null) return request;
        return new Request(request);
    }

}
