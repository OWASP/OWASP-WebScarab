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
 * SiteModelEvent.java
 *
 * Created on 11 March 2005, 09:20
 */

package org.owasp.webscarab.model;

import java.util.EventObject;

/**
 *
 * @author  rogan
 */
public class SiteModelEvent extends EventObject {
    
    public static int DATA_CHANGED = 0;
    
    public static final int URL_ADDED = 1;
    public static final int URL_CHANGED = 2;
    public static final int URL_REMOVED = 3;
    public static final int URLS_CHANGED = 4;
    
    public static final int CONVERSATION_ADDED = 11;
    public static final int CONVERSATION_CHANGED = 12;
    public static final int CONVERSATION_REMOVED = 13;
    public static final int CONVERSATIONS_CHANGED = 14;
    
    public static final int COOKIE_ADDED = 21;
    public static final int COOKIE_CHANGED = 22;
    public static final int COOKIE_REMOVED = 23;
    public static final int COOKIES_CHANGED = 24;
    
    public static final int CREDENTIAL_ADDED = 31;
    public static final int CREDENTIAL_REMOVED = 33;
    public static final int CREDENTIALS_CHANGED = 34;
    
    private int _eventType;
    private HttpUrl _url = null;
    private ConversationID _id = null;
    private Cookie _cookie = null;
//    private Credential _credential = null;
    private String _property = null;
    
    protected SiteModelEvent(Object source) {
        super(source);
    }
    
    /** Creates a new instance of SiteModelEvent */
    public SiteModelEvent(Object source, int eventType) {
        super(source);
        _eventType = eventType;
    }
    
    /** Creates a new instance of SiteModelEvent */
    public SiteModelEvent(Object source, int eventType, HttpUrl url, String property) {
        super(source);
        _eventType = eventType;
        _url = url;
        _property = property;
    }
    
    /** Creates a new instance of SiteModelEvent */
    public SiteModelEvent(Object source, int eventType, ConversationID id, String property) {
        super(source);
        _eventType = eventType;
        _id = id;
        _property = property;
    }
    
    /** Creates a new instance of SiteModelEvent */
    public SiteModelEvent(Object source, int eventType, Cookie cookie) {
        super(source);
        _eventType = eventType;
        _cookie = cookie;
    }
    
    /** Creates a new instance of SiteModelEvent */
//    public SiteModelEvent(Object source, int eventType, Credential credential) {
//        super(source);
//        _eventType = eventType;
//        _credential = credential;
//    }
    
    public int getEventType() {
        return _eventType;
    }
    
    public HttpUrl getUrl() {
        return _url;
    }
    
    public ConversationID getConversationID() {
        return _id;
    }
    
    public Cookie getCookie() {
        return _cookie;
    }
    
    public String getPropertyName() {
        return _property;
    }
    
//    public Credential getCredential() {
//        return _credential;
//    }
    
}
