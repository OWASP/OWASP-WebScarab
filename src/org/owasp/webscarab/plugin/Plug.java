/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.Conversation;

/**
 *
 * @author  rdawes
 */
public interface Plug {
    
	void addPlugin ( WebScarabPlugin plugin );
	
  String addConversation ( Conversation conversation );
	
}
