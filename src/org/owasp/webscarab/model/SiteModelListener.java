/*
 * SiteModelListener.java
 *
 * Created on August 9, 2004, 12:54 AM
 */

package org.owasp.webscarab.model;

import java.util.EventListener;

/**
 * Defines the interface required by classes wishing to listen to SiteModel events.
 *
 * NOTE: the SiteModel calls these methods while holding a read lock. This
 * means that any attempts to write to the model in the same thread will deadlock
 * immediately. These event methods should only be used to notify other threads
 * of changes, and should return pretty quickly.
 * It IS safe to perform reads from the model in this and other threads during
 * this method. The model allows multiple simultaneous readers, but only one writer.
 * @author rogan
 */
public interface SiteModelListener extends EventListener {
    
    /**
     * called after a new conversation has been added to the model
     * @param id the id of the conversation
     */    
    void conversationAdded(ConversationID id);
    
    /**
     * called after a conversation property has been changed
     * @param id the id of the conversation
     * @param property the name of the property that changed
     */    
    void conversationChanged(ConversationID id, String property);
    
    /**
     * called after a conversation has been removed from the model.
     *
     * This is actually not implemented yet, and this method is not called.
     * @param id the ID of the conversation
     * @param position the position in the overall conversation list prior to removal
     * @param urlposition the position in the per-url conversation list prior to removal
     */    
    void conversationRemoved(ConversationID id, int position, int urlposition);
    
    /**
     * called after an Url has been added to the store
     * @param url the url that was added
     */    
    void urlAdded(HttpUrl url);
    
    /**
     * called after an Url property has been changed
     * @param url the url that changed
     * @param property the name of the property that changed
     */    
    void urlChanged(HttpUrl url, String property);
    
    /**
     * called after an Url has been removed from the model
     * @param url the url that was removed
     * @param position the index of this url under its parent url
     */    
    void urlRemoved(HttpUrl url, int position);
    
    /**
     * called after a completely new cookie is added to the model
     * i.e. a new domain, new path, or new cookie name
     * @param cookie the cookie that was added
     */    
    void cookieAdded(Cookie cookie);
    
    /**
     * fired after a cookie has been removed from the model. A previous cookie 
     * might still exist.
     * @param cookie the cookie that was removed
     */    
    void cookieRemoved(Cookie cookie);
    
}
