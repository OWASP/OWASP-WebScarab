/*
 * UrlEvent.java
 *
 * Created on 13 April 2005, 04:03
 */

package org.owasp.webscarab.model;

import java.util.EventObject;

/**
 *
 * @author  rogan
 */
public class UrlEvent extends EventObject {
    
    private HttpUrl _url;
    private int _position;
    
    /** Creates a new instance of UrlEvent */
    public UrlEvent(Object source, HttpUrl url, int position) {
        super(source);
        _url = url;
        _position = position;
    }
    
    public HttpUrl getUrl() {
        return _url;
    }
    
    public int getPosition() {
        return _position;
    }
}
