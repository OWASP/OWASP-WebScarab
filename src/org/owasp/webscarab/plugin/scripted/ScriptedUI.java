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
    
    void scriptPaused();
    
    void scriptResumed();
    
    void scriptError(EvalError ee);
    
    void iteration(int i);
    
    void setEnabled(boolean enabled);
    
}
