/*
 * SwingPlugin.java
 *
 * Created on July 13, 2003, 8:08 PM
 */

package src.org.owasp.webscarab.ui.swing;

import javax.swing.JPanel;

/**
 *
 * @author  rdawes
 */
public interface SwingPlugin {

    public String getPluginName();
    
    public JPanel getPanel();
    
    public void newSession(String dir);
    
    public void openSession(String dir);
    
    public void saveSession(String dir);
    
}
