/*
 * ColumnDataEvent.java
 *
 * Created on 06 December 2004, 05:23
 */

package org.owasp.webscarab.util.swing;

import java.util.EventObject;

/**
 *
 * @author  rogan
 */
public class ColumnDataEvent extends EventObject {
    
    private Object _key;
    
    /** Creates a new instance of ColumnDataEvent */
    public ColumnDataEvent(Object source, Object key) {
        super(source);
        _key = key;
    }
    
    public Object getKey() {
        return _key;
    }
    
}
