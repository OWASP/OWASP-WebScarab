/*
 * ColumnDataListener.java
 *
 * Created on 06 December 2004, 04:54
 */

package org.owasp.webscarab.util.swing;

import java.util.EventListener;

/**
 *
 * @author  rogan
 */
public interface ColumnDataListener extends EventListener {
    
    public void dataChanged(ColumnDataEvent cde);
    
}
