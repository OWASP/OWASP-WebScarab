/*
 * ConversationID.java
 *
 * Created on July 13, 2004, 3:59 PM
 */

package org.owasp.webscarab.model;

import java.text.ParseException;

/**
 * provides a link to a conversation in the model
 * @author knoppix
 */
public class ConversationID implements Comparable {
    
    private static Object _lock = new Object();
    private static int _next = 1;
    
    private int _id;
    
    /**
     * Creates a new instance of ConversationID. Each ConversationID created using this
     * constructor will be unique (currently based on an incrementing integer value)
     */
    public ConversationID() {
        synchronized(_lock) {
            _id = _next++;
        }
    }
    
    /**
     * creates a Conversation ID based on the string provided.
     * The next no-parameter ConversationID created will be "greater" than this one.
     * @param id a string representation of the ConversationID
     * @throws ParseException if there are any errors parsing the string
     */    
    public ConversationID(String id) throws ParseException {
        synchronized (_lock) {
            try {
                _id = Integer.parseInt(id.trim());
                if (_id >= _next) {
                    _next = _id + 1;
                } else if (_id <= 0) {
                    throw new ParseException("Cannot parse '" + id + "' as a ConversationID",0);
                } 
            } catch (NumberFormatException nfe) {
                throw new ParseException("Cannot parse '" + id + "' as a ConversationID",0);
            }
        }
    }
    
    /**
     * resets the ConversationID counter to zero.
     */    
    public static void reset() {
        synchronized(_lock) {
            _next = 1;
        }
    }
    
    protected int getID() {
        return _id;
    }
    
    /**
     * shows a string representation of the ConversationID
     * @return a string representation
     */    
    public String toString() {
        return Integer.toString(_id);
    }
    
    /**
     * compares this ConversationID to another
     * @param o the other ConversationID to compare to
     * @return true if they are equal, false otherwise
     */    
    public boolean equals(Object o) {
        if (o == null || ! (o instanceof ConversationID)) return false;
        return _id == ((ConversationID)o).getID();
    }
    
    /**
     *
     * @return
     */    
    public int hashCode() {
        return _id;
    }
    
    /**
     * compares this ConversationID to another
     * @param o the other ConversationID to compare to
     * @return -1, 0 or 1 if this ConversationID is less than, equal to, or greater than the supplied parameter
     */    
    public int compareTo(Object o) {
        if (o instanceof ConversationID) {
            int thatid = ((ConversationID)o).getID();
            return _id - thatid;
        }
        return 1;
    }
    
}
