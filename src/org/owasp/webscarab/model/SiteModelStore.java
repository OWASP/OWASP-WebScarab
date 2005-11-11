/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * SiteModelStore.java
 *
 * Created on August 23, 2003, 2:38 PM
 */

package org.owasp.webscarab.model;

import java.util.Date;

/**
 * This interface defines the necessary functions for a persistent or non-persistent
 * backing store.
 * @author rdawes
 */
public interface SiteModelStore {
    
    /**
     * adds a new conversation
     * @param id the id of the new conversation
     * @param when the date the conversation was created
     * @param request the request to add
     * @param response the response to add
     */    
    int addConversation(ConversationID id, Date when, Request request, Response response);
    
    /**
     * sets a value for a property, for a specific conversation
     * @param id the conversation ID
     * @param property the name of the property
     * @param value the value to set
     */    
    void setConversationProperty(ConversationID id, String property, String value);
    
    /**
     * adds a new value to the list of values for the specified property and conversation
     * @param id the conversation id
     * @param property the name of the property
     * @param value the value to add
     */    
    boolean addConversationProperty(ConversationID id, String property, String value);
    
    /**
     * returns an array of strings containing the values that have been set for the
     * specified conversation property
     * @param id the conversation id
     * @param property the name of the property
     * @return the property values
     */    
    String[] getConversationProperties(ConversationID id, String property);
    
    /**
     * Conversations are sorted according to the natural ordering of their conversationID.
     * This method returns the position of the specified conversation in the list of conversations
     * relating to the specified URL. If the URL is null, returns the position of the conversation
     * in the overall list of conversations.
     * @return the position in the list of conversations, or -insert-1 if the conversation does not apply to the url
     * @param url acts as a filter on the overall list of conversations
     * @param id the conversation
     */    
    int getIndexOfConversation(HttpUrl url, ConversationID id);
    
    /**
     * returns the number of conversations related to the url supplied
     * @param url the url in question, or null for all conversations
     * @return the number of conversations related to the supplied URL
     */    
    int getConversationCount(HttpUrl url);
    
    /**
     * returns the ID of the conversation at position index in the list of conversations
     * related to the supplied url. If url is null, returns the position in the total
     * list of conversations.
     * @param url the url to use as a filter, or null for none
     * @param index the position in the list
     * @return the conversation id
     */    
    ConversationID getConversationAt(HttpUrl url, int index);
    
    
    /**
     * adds an entry for the specified URL, so that subsequent calls to isKnownUrl will
     * return true.
     * @param url the url to add
     */    
    void addUrl(HttpUrl url);
    
    /**
     * returns true if the url is already existing in the store, false otherwise
     * @param url the url to test
     * @return true if the url is already known, false otherwise
     */    
    boolean isKnownUrl(HttpUrl url);
    
    /**
     * sets a value for a property, for a specific URL
     * @param url the url
     * @param property the name of the property
     * @param value the value to set
     */
    void setUrlProperty(HttpUrl url, String property, String value);
    
    /**
     * adds a new value to the list of values for the specified property and url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    boolean addUrlProperty(HttpUrl url, String property, String value);
    
    /**
     * returns an array of strings containing the values that have been set for the
     * specified url property
     * @param url the url
     * @param property the name of the property
     * @return the property values
     */
    String[] getUrlProperties(HttpUrl url, String property);
    
    /**
     * returns the number of URL's that are children of the URL passed.
     * @param url the url
     * @return the number of children of the supplied url.
     */
    public int getChildCount(HttpUrl url);
    
    /**
     * returns the specified child of the URL passed.
     * @param url the url
     * @param index the index
     * @return the child at position index.
     */
    public HttpUrl getChildAt(HttpUrl url, int index);
    
    public int getIndexOf(HttpUrl url);
    
    /**
     * writes a specific Request instance to long-term storage.
     * @param id the request id
     * @param request the request
     */    
    void setRequest(ConversationID id, Request request);
    
    /**
     * Reads the requested Request class from long-term storage.
     * @return the desired Request
     * @param id The id of the specific Request
     */    
    Request getRequest(ConversationID id);
    
    /**
     * writes a specific Response instance to long-term storage.
     * @param id the response id
     * @param response the response
     */    
    void setResponse(ConversationID id, Response response);
    
    /**
     * Reads the desired Response class from long-term storage.
     * @return the desired Response
     * @param id the id of the desired Response
     */    
    Response getResponse(ConversationID id);
    
    
    /**
     * returns the number of unique cookie names in the jar
     * @return the number of unique cookie names in the jar
     */    
    int getCookieCount();
    
    /**
     * returns the number of different cookie values that have been observed for the particular cookie key
     * @param key the cookie key
     * @return the number of cookies
     */    
    int getCookieCount(String key);
    
    /**
     * returns a key which represents a cookie in the jar, basically "domain/path name"
     * @param index the number of the cookie in the jar
     * @return a key which represents a cookie in the jar, basically "domain/path name"
     */    
    String getCookieAt(int index);
    
    /**
     * returns the cookie containing the value indicated by the key and index parameters
     * @param key the cookie key
     * @param index the index. The higher the number, the more recent the cookie.
     * @return the cookie
     */    
    Cookie getCookieAt(String key, int index);
    
    /**
     * returns the most recent cookie indicated by the key parameters
     * @param key the cookie key
     * @return the cookie
     */    
    Cookie getCurrentCookie(String key);
    
    /**
     * returns the index of the provided cookie in the list of values
     * @param cookie the cookie
     * @return the index of the cookie
     */    
    int getIndexOfCookie(Cookie cookie);
    
    /**
     * returns the index of the provided cookie in the list of values
     * @param key the key
     * @param cookie the cookie
     * @return the index of the cookie
     */    
    int getIndexOfCookie(String key, Cookie cookie);
    
    /**
     * adds a new cookie to the store
     * @param cookie the cookie to add
     * @return true if the cookie did not previously exist in the store, false if it did.
     */    
    boolean addCookie(Cookie cookie);
    
    /**
     * removes a cookie from the store
     * @return true if the cookie was deleted, or false if it was not already in the store
     * @param cookie the cookie to remove
     */
    boolean removeCookie(Cookie cookie);
    
    /**
     * forces the store implementation to ensure that all external representations are
     * in a consistent state
     * @throws StoreException if there is any error writing the data
     */    
    void flush() throws StoreException;
}
