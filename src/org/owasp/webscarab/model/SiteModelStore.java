/*
 * SiteModelStore.java
 *
 * Created on August 23, 2003, 2:38 PM
 */

package org.owasp.webscarab.model;

/**
 *
 * @author  rdawes
 */
public interface SiteModelStore {

    void writeURLInfo(URLInfo[] urlinfo) throws StoreException;
    
    URLInfo[] readURLInfo() throws StoreException;
    
    /* conversations are written as we see them, not just when the program
     * exits, so we don't need a bulk-writer interface.
     */
    void writeConversations(Conversation[] conversation) throws StoreException;
    
    Conversation[] readConversations() throws StoreException;
    
    void writeRequest(String id, Request request) throws StoreException;
    
    Request readRequest(String id) throws StoreException;
    
    void writeResponse(String id, Response response) throws StoreException;
    
    Response readResponse(String id) throws StoreException;
    
}
