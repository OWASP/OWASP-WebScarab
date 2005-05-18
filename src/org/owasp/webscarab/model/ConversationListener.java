/*
 * ConversationListener.java
 *
 * Created on 13 April 2005, 03:20
 */

package org.owasp.webscarab.model;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface ConversationListener extends EventListener {
    
    void conversationAdded(ConversationEvent evt);
    
    void conversationChanged(ConversationEvent evt);
    
    void conversationRemoved(ConversationEvent evt);
    
    void conversationsChanged();
    
}
