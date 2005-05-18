/*
 * SessionIDListener.java
 *
 * Created on 29 April 2005, 08:28
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.plugin.PluginListener;

/**
 *
 * @author  rogan
 */
public interface SessionIDListener extends PluginListener {
    
    void sessionIDAdded(String key, int index);
    
    void sessionIDsChanged();
    
    void calculatorChanged(String key);
    
}
