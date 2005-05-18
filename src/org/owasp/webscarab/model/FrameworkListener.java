/*
 * FrameworkListener.java
 *
 * Created on 13 April 2005, 05:17
 */

package org.owasp.webscarab.model;

/**
 *
 * @author  rogan
 */
public interface FrameworkListener extends java.util.EventListener {
    
    void cookieAdded(FrameworkEvent evt);
    
    void cookieRemoved(FrameworkEvent evt);
    
    void cookiesChanged();
    
    void conversationPropertyChanged(FrameworkEvent evt);
    
    void urlPropertyChanged(FrameworkEvent evt);
    
}
