/*
 * Link.java
 *
 * Created on August 7, 2003, 10:28 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rdawes
 */
public class Link {
    
    private HttpUrl _url;
    private String _referer;
    
    /** Creates a new instance of Link */
    public Link(HttpUrl url, String referer) {
        _url = url;
        _referer = referer;
    }
    
    public HttpUrl getURL() {
        return _url;
    }
    
    public String getReferer() {
        return _referer;
    }
    
    public String toString() {
        return _url.toString() + " via " + _referer;
    }
}
