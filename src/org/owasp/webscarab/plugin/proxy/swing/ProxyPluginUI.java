/*
 * ProxyPluginUI.java
 *
 * Created on 15 December 2004, 11:13
 */

package org.owasp.webscarab.plugin.proxy.swing;

import org.owasp.webscarab.plugin.PluginUI;
import javax.swing.JPanel;

/**
 *
 * @author  rogan
 */
public interface ProxyPluginUI extends PluginUI {

    JPanel getPanel();
    
}
