/*
 * ConversationEvent.java
 *
 * Created on 13 April 2005, 03:25
 */

package org.owasp.webscarab.model;

import java.util.EventObject;

/**
 *
 * @author  rogan
 */
public class ConversationEvent extends EventObject {
    
    private ConversationID _id;
    private int _position;
    
    /** Creates a new instance of ConversationEvent */
    public ConversationEvent(Object source, ConversationID id, int position) {
        super(source);
        _id = id;
        _position = position;
    }
    
    public ConversationID getConversationID() {
        return _id;
    }
    
    public int getPosition() {
        return _position;
    }
    
}
