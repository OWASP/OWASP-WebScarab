/*
 * ExceptionHandler.java
 *
 * Created on 09 February 2005, 04:44
 */

package org.owasp.webscarab.ui.swing;

import java.awt.Component;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import java.io.PrintStream;
import org.owasp.webscarab.util.swing.DocumentOutputStream;

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
        System.setProperty("sun.awt.exception.handler", "");
        t.printStackTrace();
        DocumentOutputStream dos = new DocumentOutputStream();
        t.printStackTrace(new PrintStream(dos));
        JTextArea ta = new JTextArea(dos.getDocument());
        ta.setEditable(false);
        ta.setTabSize(8);
        ta.setBackground(new java.awt.Color(204,204,204));
        JScrollPane sp = new JScrollPane(ta);
        sp.setPreferredSize(new java.awt.Dimension(600,300));
        JOptionPane.showMessageDialog(_parentComponent, sp, "An unhandled exception occurred!", JOptionPane.ERROR_MESSAGE);
        System.setProperty("sun.awt.exception.handler", ExceptionHandler.class.getName());
    }
    
}
