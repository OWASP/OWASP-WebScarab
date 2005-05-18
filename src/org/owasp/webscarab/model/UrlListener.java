/*
 * UrlListener.java
 *
 * Created on 13 April 2005, 04:01
 */

package org.owasp.webscarab.model;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface UrlListener extends EventListener {

    void urlAdded(UrlEvent evt);
    
    void urlChanged(UrlEvent evt);
    
    void urlRemoved(UrlEvent evt);
    
    void urlsChanged();
    
}
