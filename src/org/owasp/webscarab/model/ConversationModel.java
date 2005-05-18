/*
 * ConversationModel.java
 *
 * Created on 13 April 2005, 03:00
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

/**
 *
 * @author  rogan
 */
public interface ConversationModel {
    
    int getConversationCount(HttpUrl url);
    
    ConversationID getConversationAt(HttpUrl url, int index);
    
    int getIndexOfConversation(HttpUrl url, ConversationID id);
    
    Sync readLock();
    
    String getRequestMethod(ConversationID id);
    
    HttpUrl getRequestUrl(ConversationID id);
    
    String getResponseStatus(ConversationID id);
    
    Request getRequest(ConversationID id);
    
    Response getResponse(ConversationID id);
    
    void addConversationListener(ConversationListener listener);
    
    void removeConversationListener(ConversationListener listener);
    
}
