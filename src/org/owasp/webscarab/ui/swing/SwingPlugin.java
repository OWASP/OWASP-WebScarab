/*
 * SwingPlugin.java
 *
 * Created on July 13, 2003, 8:08 PM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JPanel;
import javax.swing.Action;

/**
 *
 * @author  rdawes
 */
public interface SwingPlugin {

    String getPluginName();
    
    JPanel getPanel();
    
    Action[] getURLActions();
    
    Action[] getConversationActions();
    
}
