/*
 * ManualRequestUI.java
 *
 * Created on August 8, 2004, 9:51 PM
 */

package org.owasp.webscarab.plugin.manualrequest;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.PluginUI;

/**
 *
 * @author  knoppix
 */
public interface ManualRequestUI extends PluginUI {
    
    void requestChanged(Request request);
    
    void responseChanged(Response response);
    
}
