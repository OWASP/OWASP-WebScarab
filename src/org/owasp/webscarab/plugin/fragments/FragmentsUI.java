/*
 * FragmentsUI.java
 *
 * Created on 08 December 2004, 07:40
 */

package org.owasp.webscarab.plugin.fragments;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.PluginUI;

/**
 *
 * @author  rogan
 */
public interface FragmentsUI extends PluginUI {
    
    void fragmentAdded(HttpUrl url, ConversationID id, String type, String key);
    
}
