/*
 * ScriptedUI.java
 *
 * Created on 03 January 2005, 12:37
 */

package org.owasp.webscarab.plugin.scripted;

import java.io.PrintStream;
import bsh.EvalError;

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
    
}
