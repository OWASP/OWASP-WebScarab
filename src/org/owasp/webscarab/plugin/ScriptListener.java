/*
 * ScriptListener.java
 *
 * Created on 09 January 2005, 08:32
 */

package org.owasp.webscarab.plugin;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface ScriptListener extends EventListener {
    
    void hooksChanged();
    
    void hookStarted(String plugin, Hook hook);
    
    void hookEnded(String plugin, Hook hook);
    
    void scriptAdded(String plugin, Hook hook, Script script);
    
    void scriptRemoved(String plugin, Hook hook, Script script);
    
    void scriptStarted(String plugin, Hook hook, Script script);
    
    void scriptEnded(String plugin, Hook hook, Script script);
    
    void scriptChanged(String plugin, Hook hook, Script script);
    
    void scriptError(String plugin, Hook hook, Script script, Throwable error);
    
}
