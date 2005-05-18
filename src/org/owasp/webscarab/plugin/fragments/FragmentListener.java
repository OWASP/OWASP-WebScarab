/*
 * FragmentListener.java
 *
 * Created on 13 April 2005, 06:23
 */

package org.owasp.webscarab.plugin.fragments;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.PluginListener;

/**
 *
 * @author  rogan
 */
public interface FragmentListener extends PluginListener {
    
    void fragmentAdded(HttpUrl url, ConversationID id, String type, String key);
    
    void fragmentAdded(String type, String key, int position);
    
    void fragmentsChanged();
    
}
