/*
 * SiteModelStore.java
 *
 * Created on August 23, 2003, 2:38 PM
 */

package org.owasp.webscarab.model;

/** This interface specifies what is required to persist the SiteModel, and retrieve
 * it again
 * @author rdawes
 */
public interface SiteModelStore {

    /** Saves an array of URLInfo classes to long-term storage
     * @param urlinfo an array of URLInfo's to write out
     * @throws StoreException if there are any problems writing to the Store
     */    
    void writeURLInfo(URLInfo[] urlinfo) throws StoreException;
    
    /** Reads the URLInfo classes from long-term storage.
     * @return an array of URLInfo classes
     * @throws StoreException if there are any problems reading from the Store
     */    
    URLInfo[] readURLInfo() throws StoreException;
    
    /** writes an array of Conversation classes to long-term storage.
     * @param conversation the array of Conversations
     * @throws StoreException if there are any problems writing to the Store
     */    
    void writeConversations(Conversation[] conversation) throws StoreException;
    
    /** Reads the Conversation classes from long-term storage.
     * @return an array of Conversation classes
     * @throws StoreException if there are any problems reading from the Store
     */    
    Conversation[] readConversations() throws StoreException;
    
    /** writes a specific Request instance to long-term storage.
     * @param id the request id
     * @param request the request
     * @throws StoreException if there are any problems writing to the Store
     */    
    void writeRequest(String id, Request request) throws StoreException;
    
    /** Reads the requested Request class from long-term storage.
     * @return the desired Request
     * @throws StoreException if there are any problems reading from the Store
     * @param id The id of the specific Request
     */    
    Request readRequest(String id) throws StoreException;
    
    /** writes a specific Response instance to long-term storage.
     * @param id the response id
     * @param response the response
     * @throws StoreException if there are any problems writing to the Store
     */    
    void writeResponse(String id, Response response) throws StoreException;
    
    /** Reads the desired Response class from long-term storage.
     * @return the desired Response
     * @throws StoreException if there are any problems reading from the Store
     * @param id the id of the desired Response
     */    
    Response readResponse(String id) throws StoreException;
    
    /** writes an array of Cookie classes to long-term storage.
     * @param cookie the array of Cookies
     * @throws StoreException if there are any problems writing to the Store
     */    
    void writeCookies(Cookie[] cookie) throws StoreException;
    
    /** Reads the Cookie classes from long-term storage.
     * @return an array of Cookie classes
     * @throws StoreException if there are any problems reading from the Store
     */    
    Cookie[] readCookies() throws StoreException;
}
