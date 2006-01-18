/*
 * ConversationHandler.java
 *
 * Created on 10 January 2006, 06:24
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.httpclient;

import java.io.IOException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author rdawes
 */
public interface ConversationHandler {
    
    void responseReceived(Response response);
    
    void requestError(Request request, IOException ioe);
    
}
