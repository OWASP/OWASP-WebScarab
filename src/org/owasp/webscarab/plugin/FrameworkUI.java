/*
 * FrameworkUI.java
 *
 * Created on September 7, 2004, 6:00 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.SiteModel;

/**
 * specifies the interface between framework and its user interface
 * @author knoppix
 */
public interface FrameworkUI {
    
    /**
     * instructs the UI that the model has changed
     * @param model the new model
     */    
    void setModel(SiteModel model);
    
}
