package org.owasp.webscarab.plugin;

import java.util.Date;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

public class FrameworkModelWrapper {

	private FrameworkModel _frameworkModel;
	
	public FrameworkModelWrapper(FrameworkModel frameworkModel) {
		this._frameworkModel = frameworkModel;
	}
	
    public String getConversationOrigin(ConversationID id) {
        return _frameworkModel.getConversationOrigin(id);
    }
    
    public Date getConversationDate(ConversationID id) {
    	return _frameworkModel.getConversationDate(id);
    }
    
    /**
     * returns the url of the conversation in question
     * @param conversation the conversation
     * @return the url
     */
    
    public HttpUrl getRequestUrl(ConversationID conversation) {
    	return _frameworkModel.getRequestUrl(conversation);
    }
    
    /**
     * sets the specified property of the conversation
     * @param conversation the conversation ID
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setConversationProperty(ConversationID conversation, String property, String value) {
    	_frameworkModel.setConversationProperty(conversation, property, value);
    }
    
    /**
     * adds the value to a list of existing values for the specified property and conversation
     * @param conversation the conversation
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addConversationProperty(ConversationID conversation, String property, String value) {
    	return _frameworkModel.addConversationProperty(conversation, property, value);
    }
    
    /**
     * returns a String containing the value that has been identified for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getConversationProperty(ConversationID conversation, String property) {
    	return getConversationProperty(conversation, property);
    }
    
    public String getRequestMethod(ConversationID id) {
        return _frameworkModel.getRequestMethod(id);
    }
    
    public String getResponseStatus(ConversationID id) {
        return _frameworkModel.getResponseStatus(id);
    }
    
    /**
     * returns a String array containing the values that has been set for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getConversationProperties(ConversationID conversation, String property) {
    	return _frameworkModel.getConversationProperties(conversation, property);
    }
    
    /**
     * sets the specified property of the url
     * @param url the url
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setUrlProperty(HttpUrl url, String property, String value) {
    	_frameworkModel.setUrlProperty(url, property, value);
    }
    
    /**
     * adds the value to a list of existing values for the specified property and Url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addUrlProperty(HttpUrl url, String property, String value) {
    	return _frameworkModel.addUrlProperty(url, property, value);
    }
    
    /**
     * returns a String array containing the values that has been set for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getUrlProperties(HttpUrl url, String property) {
    	return _frameworkModel.getUrlProperties(url, property);
    }
    
    /**
     * returns a String containing the value that has been identified for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getUrlProperty(HttpUrl url, String property) {
    	return _frameworkModel.getUrlProperty(url, property);
    }
    
    /**
     * returns the request corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the request
     */
    public Request getRequest(ConversationID conversation) {
    	return _frameworkModel.getRequest(conversation);
    }
    
    /**
     * returns the response corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the response
     */
    public Response getResponse(ConversationID conversation) {
    	return _frameworkModel.getResponse(conversation);
    }
    
    /**
     * returns the number of uniquely named cookies that have been added to the model.
     * This does not consider changes in value of cookies.
     * @return the number of cookies
     */
    public int getCookieCount() {
    	return _frameworkModel.getCookieCount();
    }
    
    /**
     * returns the number of unique values that have been observed for the specified cookie
     * @param key a key identifying the cookie
     * @return the number of values in the model
     */
    public int getCookieCount(String key) {
    	return _frameworkModel.getCookieCount(key);
    }
    
    /**
     * returns a key representing the cookie name at the position specified
     * @return a key which can be used to get values for this cookie
     * @param index which cookie in the list
     */
    public String getCookieAt(int index) {
    	return _frameworkModel.getCookieAt(index);
    }
    
    /**
     * returns the actual Cookie corresponding to the key and position specified
     * @param key the cookie identifier
     * @param index the position in the list
     * @return the cookie
     */
    public Cookie getCookieAt(String key, int index) {
    	return _frameworkModel.getCookieAt(key, index);
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(Cookie cookie) {
    	return _frameworkModel.getIndexOfCookie(cookie);
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(String key, Cookie cookie) {
    	return _frameworkModel.getIndexOfCookie(key, cookie);
    }
    
    public Cookie getCurrentCookie(String key) {
    	return _frameworkModel.getCurrentCookie(key);
    }
    
    /**
     * adds a cookie to the model
     * @param cookie the cookie to add
     */
    public void addCookie(Cookie cookie) {
    	_frameworkModel.addCookie(cookie);
    }
    
    /**
     * removes a cookie from the model
     * @param cookie the cookie to remove
     */
    public void removeCookie(Cookie cookie) {
    	_frameworkModel.removeCookie(cookie);
    }
    
    /**
     * returns an array of cookies that would be applicable to a request sent to the url.
     * @param url the url
     * @return an array of cookies, or a zero length array if there are none applicable.
     */
    public Cookie[] getCookiesForUrl(HttpUrl url) {
    	return _frameworkModel.getCookiesForUrl(url);
    }

}
