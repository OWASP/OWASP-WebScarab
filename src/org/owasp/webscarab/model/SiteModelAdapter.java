/*
 * SiteModelAdapter.java
 *
 * Created on September 6, 2004, 5:39 PM
 */

package org.owasp.webscarab.model;

/**
 * provides an adapter between the SiteListener interface and implementations, so that
 * empty methods need not be created
 * @author rogan
 */
public class SiteModelAdapter implements SiteModelListener {
    
    /** Creates a new instance of SiteModelAdapter */
    public SiteModelAdapter() {
    }
    
    /**
     * called after a new conversation has been added to the model
     * @param id the id of the conversation
     */
    public void conversationAdded(ConversationID id) {}
    
    /**
     * called after a conversation property has been changed
     * @param id the id of the conversation
     * @param property the name of the property that changed
     */
    public void conversationChanged(ConversationID id, String property) {}
    
    /**
     * called after a conversation has been removed from the model.
     *
     * This is actually not implemented yet, and this method is not called.
     * @param id the ID of the conversation
     * @param position the position in the overall conversation list prior to removal
     * @param urlposition the position in the per-url conversation list prior to removal
     */
    public void conversationRemoved(ConversationID id, int position, int urlposition) {}
    
    /**
     * called after an Url has been added to the store
     * @param url the url that was added
     */
    public void urlAdded(HttpUrl url) {}
    
    /**
     * called after an Url property has been changed
     * @param url the url that changed
     * @param property the name of the property that changed
     */
    public void urlChanged(HttpUrl url, String property) {}
    
    /**
     * called after an Url has been removed from the model
     * @param url the url that was removed
     * @param position the index of this url under its parent url
     */
    public void urlRemoved(HttpUrl url, int position) {}
    
    /**
     * called after a completely new cookie is added to the model
     * i.e. a new domain, new path, or new cookie name
     * @param cookie the cookie that was added
     */    
    public void cookieAdded(Cookie cookie) {}
    
    /**
     * fired after a cookie has been removed from the model. A previous cookie 
     * might still exist.
     * @param cookie the cookie that was removed
     */    
    public void cookieRemoved(Cookie cookie) {}
    
}
