/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

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
    
    public ConversationID(int id) {
        synchronized (_lock) {
            _id = id;
            if (_id >= _next) {
                _next = _id + 1;
            } else if (_id <= 0) {
                throw new IllegalArgumentException("Cannot use a negative ConversationID");
            } 
        }        
    }
    
    /**
     * creates a Conversation ID based on the string provided.
     * The next no-parameter ConversationID created will be "greater" than this one.
     * @param id a string representation of the ConversationID
     */    
    public ConversationID(String id) {
        this(Integer.parseInt(id.trim()));
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
