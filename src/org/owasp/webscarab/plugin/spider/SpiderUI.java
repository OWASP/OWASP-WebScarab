/*
 * SpiderUI.java
 *
 * Created on July 21, 2004, 3:31 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.plugin.PluginUI;

/**
 *
 * @author  knoppix
 */
public interface SpiderUI extends PluginUI {
    
    void linkQueued(Link link);
    
    void linkDequeued(Link link);
    
}
