/*
 * PluginUI.java
 *
 * Created on September 7, 2004, 6:03 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.SiteModel;

/**
 *
 * @author  knoppix
 */
public interface PluginUI {
    
    String getPluginName();
    
    void setModel(SiteModel model);
    
    void setEnabled(boolean enabled);
    
}
