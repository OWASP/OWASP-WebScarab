/*
 * BeanShellUI.java
 *
 * Created on August 20, 2004, 6:43 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.PrintStream;

/**
 *
 * @author  knoppix
 */
public interface BeanShellUI {
    
    PrintStream getOut();
    
    PrintStream getErr();
    
}
