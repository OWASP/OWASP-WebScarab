/*
 * ScriptedUI.java
 *
 * Created on 03 January 2005, 12:37
 */

package org.owasp.webscarab.plugin.scripted;

import java.io.PrintStream;
import java.io.File;

/**
 *
 * @author  rogan
 */
public interface ScriptedUI {
    
    PrintStream getOutputStream();
    
    PrintStream getErrorStream();
    
    void scriptStarted();
    
    void scriptStopped();
    
    void scriptError(String reason, Throwable error);
    
    void setEnabled(boolean enabled);
    
    void scriptFileChanged(File file);
    
    void scriptLanguageChanged(String language);
    
    void scriptChanged(String script);
}
