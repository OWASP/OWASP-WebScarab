/*
 * StoreException.java
 *
 * Created on August 23, 2003, 2:43 PM
 */

package org.owasp.webscarab.model;

/**
 *
 * @author  rdawes
 */
public class StoreException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>StoreException</code> without detail message.
     */
    public StoreException() {
    }
    
    
    /**
     * Constructs an instance of <code>StoreException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public StoreException(String msg) {
        super(msg);
    }
}
