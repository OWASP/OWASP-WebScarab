/*
 * ExceptionHandler.java
 *
 * Created on 09 February 2005, 04:44
 */

package org.owasp.webscarab.ui.swing;

import java.awt.Component;

import javax.swing.JOptionPane;

/**
 *
 * @author  rogan
 */
public class ExceptionHandler {
    
    private static Component _parentComponent = null;
    
    /** Creates a new instance of ExceptionHandler */
    public ExceptionHandler() {
    }
    
    public static void setParentComponent(Component parentComponent) {
        _parentComponent = parentComponent;
    }
    
    public void handle(Throwable t) {
        StackTraceElement[] stackTrace = t.getStackTrace();
        Object[] message = new Object[stackTrace.length+1];
        System.arraycopy(stackTrace, 0, message, 1, stackTrace.length);
        message[0] = t.toString();
        JOptionPane.showMessageDialog(_parentComponent, message, "An unhandled exception occurred!", JOptionPane.ERROR_MESSAGE);
        t.printStackTrace();
    }
    
}
