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
 * SiteModel.java
 *
 * Created on July 13, 2004, 3:58 PM
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

/**
 * Provides a model of the conversations that have been seen
 * @author rogan
 */
public interface SiteModel {
    
    Sync readLock();
    
    /**
     * reserve a conversation ID for later use. This is mostly used by the Proxy plugin
     * to allow it to add conversations in the order that they are seen, not in the
     * order that they are completed.
     * @return a new ConversationID
     */    
    ConversationID reserveConversationID();
    
    /**
     * adds a request and a response to the model, also specifying which plugin caused
     * it.
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     * @return the ConversationID that identifies this conversation
     */    
    ConversationID addConversation(Request request, Response response, String origin);
    
    /**
     * adds a request and a response to the model, also specifying which plugin caused
     * it.
     * @param id the previously reserved ConversationID that identifies this conversation
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     */
    void addConversation(ConversationID id, Request request, Response response, String origin);
    
    /**
     * returns the url of the conversation in question
     * @param conversation the conversation
     * @return the url
     */
    HttpUrl getUrlOf(ConversationID conversation);
    
    /**
     * sets the specified property of the conversation
     * @param conversation the conversation ID
     * @param property the name of the property to change
     * @param value the value to use
     */    
    void setConversationProperty(ConversationID conversation, String property, String value);
    
    /**
     * adds the value to a list of existing values for the specified property and conversation
     * @param conversation the conversation
     * @param property the name of the property
     * @param value the value to add
     */    
    boolean addConversationProperty(ConversationID conversation, String property, String value);
    
    /**
     * returns a String containing the value that has been identified for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    String getConversationProperty(ConversationID conversation, String property);
    
    /**
     * returns a String array containing the values that has been set for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    String[] getConversationProperties(ConversationID conversation, String property);
    
    /**
     * the total number of conversations that have been added to the model
     * @return the total number of conversations in the model
     */
    int getConversationCount();
    
    /**
     * the number of conversations related to the specified url
     *
     * Note that an url with a query is not considered to be the same as the url without the query, for these purposes
     * @param url the url
     * @return the number of conversations related to the specified URL
     */    
    int getConversationCount(HttpUrl url);
    
    /**
     * obtains the conversation ID of the conversation at the specified position in the
     * list. Conversations are sorted according to the natural ordering of
     * ConversationID.
     * @return the conversation ID
     * @param index the position in the list
     */
    ConversationID getConversationAt(int index);
    
    /**
     * obtains the conversation ID of the conversation at the specified position in the
     * list of conversations related to the specified URL. Conversations are sorted
     * according to the natural ordering of ConversationID.
     * @param url the url
     * @param index the index
     * @return the conversation ID
     */    
    ConversationID getConversationAt(HttpUrl url, int index);
    
    /**
     * the position of the supplied conversation id in the list. Conversations are
     * sorted according to the natural ordering on ConversationID
     * @param conversation the conversation ID to look up
     * @return the position in the list, or the insertion point if it is not in the list
     */
    int getIndexOfConversation(ConversationID conversation);
    
    /**
     * the position of the supplied conversation id in the list of conversations
     * related to the specified URL. Conversations are sorted according to the natural
     * ordering of ConversationID
     * @param url the url
     * @param conversation the conversation ID to look up
     * @return the position in the list, or the insertion point if it is not in the list
     */    
    int getIndexOfConversation(HttpUrl url, ConversationID conversation);
    
    /**
     * sets the specified property of the url
     * @param url the url
     * @param property the name of the property to change
     * @param value the value to use
     */
    void setUrlProperty(HttpUrl url, String property, String value);
    
    /**
     * adds the value to a list of existing values for the specified property and Url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    boolean addUrlProperty(HttpUrl url, String property, String value);
    
    /**
     * returns a String array containing the values that has been set for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    String[] getUrlProperties(HttpUrl url, String property);
    
    /**
     * returns a String containing the value that has been identified for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    String getUrlProperty(HttpUrl url, String property);
    
    /**
     * returns the number of urls that logically fall directly "under" the provided
     * URL. That is, the number of direct descendants in the tree. This EXCLUDES queries
     * @param parent the url
     * @return the number of children
     */    
    int getChildUrlCount(HttpUrl parent);
    
    /**
     * returns the child URL at the position specified
     * @param parent the parent url
     * @param index the position
     * @return the child at the position specified
     */    
    HttpUrl getChildUrlAt(HttpUrl parent, int index);
    
    int getIndexOfUrl(HttpUrl url);
    
    int getIndexOfQuery(HttpUrl url);
    
    /**
     * returns the number of urls that logically fall directly "under" the provided
     * URL. That is, the number of direct descendants in the tree. This EXCLUDES queries
     * @param parent the url
     * @return the number of children
     */    
    int getQueryCount(HttpUrl parent);
    
    /**
     * returns the child URL at the position specified
     * @param parent the parent url
     * @param index the position
     * @return the child at the position specified
     */    
    HttpUrl getQueryAt(HttpUrl parent, int index);
    
    /**
     * returns the request corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the request
     */    
    Request getRequest(ConversationID conversation);
    
    /**
     * returns the response corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the response
     */    
    Response getResponse(ConversationID conversation);
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    void addModelListener(SiteModelListener listener);
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    void removeModelListener(SiteModelListener listener);
    
    /**
     * returns the number of uniquely named cookies that have been added to the model.
     * This does not consider changes in value of cookies.
     * @return the number of cookies
     */
    int getCookieCount();
    
    /**
     * returns the number of unique values that have been observed for the specified cookie
     * @param key a key identifying the cookie
     * @return the number of values in the model
     */    
    int getCookieCount(String key);
    
    /**
     * returns a key representing the cookie name at the position specified
     * @return a key which can be used to get values for this cookie
     * @param index which cookie in the list
     */    
    String getCookieAt(int index);
    
    /**
     * returns the actual Cookie corresponding to the key and position specified
     * @param key the cookie identifier
     * @param index the position in the list
     * @return the cookie
     */    
    Cookie getCookieAt(String key, int index);
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */    
    int getIndexOfCookie(Cookie cookie);
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */    
    int getIndexOfCookie(String key, Cookie cookie);
    
    Cookie getCurrentCookie(String key);
    
    /**
     * adds a cookie to the model
     * @param cookie the cookie to add
     */    
    void addCookie(Cookie cookie);
    
    /**
     * removes a cookie from the model
     * @param cookie the cookie to remove
     */    
    void removeCookie(Cookie cookie);
    
    /**
     * returns an array of cookies that would be applicable to a request sent to the url.
     * @param url the url
     * @return an array of cookies, or a zero length array if there are none applicable.
     */    
    Cookie[] getCookiesForUrl(HttpUrl url);
    
}
