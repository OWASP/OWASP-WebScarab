/*
 * Link.java
 *
 * Created on August 7, 2003, 10:28 PM
 */

package org.owasp.webscarab.plugin.spider;

import java.net.URL;

/**
 *
 * @author  rdawes
 */
public class Link {
    
    private URL _url;
    private URL _referer;
    private String _type = null; // href, img, frame, etc
    
    /** Creates a new instance of Link */
    public Link(URL url, URL referer) {
        _url = url;
        _referer = referer;
    }
    
    public URL getURL() {
        return _url;
    }
    
    public URL getReferer() {
        return _referer;
    }
    
    public void setType(String type) {
        _type = type;
    }
    
    public String getType() {
        return _type;
    }

}
