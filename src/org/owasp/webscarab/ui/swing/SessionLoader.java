/*
 * SessionLoader.java
 *
 * Created on September 7, 2004, 6:52 PM
 */

package org.owasp.webscarab.ui.swing;

import java.awt.Component;

import org.owasp.webscarab.plugin.Framework;

/**
 *
 * @author  knoppix
 */
public interface SessionLoader {

    void newSession(Component parent, Framework framework);
    
    void openSession(Component parent, Framework framework);
    
}
