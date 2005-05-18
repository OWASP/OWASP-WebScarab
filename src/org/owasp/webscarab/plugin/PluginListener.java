/*
 * PluginListener.java
 *
 * Created on 25 April 2005, 07:23
 */

package org.owasp.webscarab.plugin;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface PluginListener extends EventListener {
    
    void pluginStatusChanged(String status);
    
    void pluginRunStatusChanged(boolean running, boolean stopping);
    
}
