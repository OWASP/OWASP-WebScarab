/*
 * ConversationCriteria.java
 *
 * Created on May 13, 2004, 10:35 AM
 */

package org.owasp.webscarab.util;

/**
 *
 * @author  rdawes
 */
public class ConversationCriteria {
    
    private String _logic;
    private String _location;
    private String _operation;
    private String _match;
    
    /** Creates a new instance of ConversationCriteria */
    public ConversationCriteria(String logic, String location, String operation, String match) {
        if (logic == null || location == null || operation == null || match == null) {
            throw new NullPointerException("Criteria parameters may not be null");
        }
        _logic = logic;
        _location = location;
        _operation = operation;
        _match = match;
    }
    
    public String getLogic() {
        return _logic;
    }
    
    public String getLocation() {
        return _location;
    }
    
    public String getOperation() {
        return _operation;
    }
    
    public String getMatch() {
        return _match;
    }
    
}
