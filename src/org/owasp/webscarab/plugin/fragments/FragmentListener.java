/*
 * FragmentListener.java
 *
 * Created on 13 April 2005, 06:23
 */

package org.owasp.webscarab.plugin.fragments;

import java.util.EventListener;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public interface FragmentListener extends EventListener {
    
    void fragmentAdded(HttpUrl url, ConversationID id, String type, String key);
    
    void fragmentAdded(String type, String key, int position);
    
    void fragmentsChanged();
    
}
