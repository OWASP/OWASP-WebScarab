/*
 * SessionIDListener.java
 *
 * Created on 19 October 2004, 11:14
 */

package org.owasp.webscarab.plugin.sessionid.swing;

import java.util.EventListener;
import org.owasp.webscarab.plugin.sessionid.SessionID;

/**
 *
 * @author  rogan
 */
public interface SessionIDListener extends EventListener {

    void idAdded(String key, int index);
    
    void idsChanged();
    
}
