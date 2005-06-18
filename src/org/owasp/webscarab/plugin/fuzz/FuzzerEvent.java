/*
 * FuzzerEvent.java
 *
 * Created on 11 March 2005, 10:51
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public class FuzzerEvent {
    
    public final static int FUZZHEADER_ADDED = 101;
    public final static int FUZZHEADER_CHANGED = 102;
    public final static int FUZZHEADER_REMOVED = 103;
    public final static int FUZZPARAMETER_ADDED = 104;
    public final static int FUZZPARAMETER_CHANGED = 105;
    public final static int FUZZPARAMETER_REMOVED = 106;
    
    private int _type;
    private int _row;
    
    /** Creates a new instance of FuzzerEvent */
    public FuzzerEvent(Object source, int eventType, int row) {
        _type = eventType;
        _row = row;
    }
    
    public int getType() {
        return _type;
    }
    
    public int getRow() {
        return _row;
    }
    
}
