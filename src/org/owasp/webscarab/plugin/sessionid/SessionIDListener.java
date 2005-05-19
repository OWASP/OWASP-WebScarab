/*
 * SessionIDListener.java
 *
 * Created on 29 April 2005, 08:28
 */

package org.owasp.webscarab.plugin.sessionid;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface SessionIDListener extends EventListener {
    
    void sessionIDAdded(String key, int index);
    
    void sessionIDsChanged();
    
    void calculatorChanged(String key);
    
}
