/*
 * SwingPlugin.java
 *
 * Created on July 13, 2003, 8:08 PM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JPanel;

/**
 *
 * @author  rdawes
 */
public interface SwingPlugin {

    String getPluginName();
    
    JPanel getPanel();
    
    void newSession(String dir);
    
    void openSession(String dir);
    
    void saveSession(String dir);
    
}
