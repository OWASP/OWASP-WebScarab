/*
 * ConversationURLFilter.java
 *
 * Created on March 30, 2004, 8:51 AM
 */

package org.owasp.webscarab.util;

import java.net.URL;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.Request;

public class ConversationURLFilter extends Filter {

    private String _url = null;
    
    public ConversationURLFilter() {
    }
    
    public ConversationURLFilter(String url) {
        _url = url;
    }
    
    public void setURL(String url) {
        if (url != _url) {
            _url = url;
            fireFilterChanged();
        }
    }
        
    public String getURL() {
        return _url;
    }

    public boolean filtered(Object object) {
        if (_url == null) {
            return false;
        }
        if (object == null || ! (object instanceof Conversation)) {
            return true;
        }
        Conversation c = (Conversation) object;
        String url = c.getProperty("URL");
        if (_url == null || url == null) {
            return false;
        }
        if (!_url.equals(url)) {
            return true;
        }
        return false;
    }

}