/*
 * SessionIDListener.java
 *
 * Created on August 9, 2004, 8:13 PM
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.plugin.PluginUI;

/**
 *
 * @author  knoppix
 */
public interface SessionIDAnalysisUI extends PluginUI {
    
    void setEnabled(boolean enabled);
    
    void sessionIDAdded(String key, int index);
    
    void sessionIDsChanged();
    
    void calculatorChanged(String key);
    
}
