/*
 * Link.java
 *
 * Created on August 7, 2003, 10:28 PM
 */

package org.owasp.webscarab.plugin.spider;

/**
 *
 * @author  rdawes
 */
public class Link {
    
    private String _url;
    private String _referer;
    private String _type = null; // href, img, frame, etc
    
    /** Creates a new instance of Link */
    public Link(String url, String referer) {
        _url = url;
        _referer = referer;
    }
    
    public String getURL() {
        return _url;
    }
    
    public String getReferer() {
        return _referer;
    }
    
    public void setType(String type) {
        _type = type;
    }
    
    public String getType() {
        return _type;
    }

}
