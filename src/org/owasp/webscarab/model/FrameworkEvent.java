/*
 * FrameworkEvent.java
 *
 * Created on 13 April 2005, 05:11
 */

package org.owasp.webscarab.model;

import java.util.EventObject;

/**
 *
 * @author  rogan
 */
public class FrameworkEvent extends EventObject {
    
    private ConversationID _id = null;
    private HttpUrl _url = null;
    private Cookie _cookie = null;
    private String _property = null;
    
    /** Creates a new instance of FrameworkEvent */
    public FrameworkEvent(Object source, ConversationID id, String property) {
        super(source);
        _id = id;
        _property = property;
    }
    
    public FrameworkEvent(Object source, HttpUrl url, String property) {
        super(source);
        _url = url;
        _property = property;
    }
    
    public FrameworkEvent(Object source, Cookie cookie) {
        super(source);
        _cookie = cookie;
    }
    
    public ConversationID getConversationID() {
        return _id;
    }
    
    public HttpUrl getUrl() {
        return _url;
    }
    
    public Cookie getCookie() {
        return _cookie;
    }
    
    public String getPropertyName() {
        return _property;
    }
    
}
