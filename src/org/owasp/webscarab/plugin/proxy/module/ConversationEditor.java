/*
 * ConversationEditor.java
 *
 * Created on August 5, 2003, 12:06 AM
 */

package org.owasp.webscarab.plugin.proxy.module;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public interface ConversationEditor {
    
    public Request editRequest(Request request);
    
    public Response editResponse(Request request, Response response);
    
}
