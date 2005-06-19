/*
 * FuzzSource.java
 *
 * Created on 17 June 2005, 02:43
 */

package org.owasp.webscarab.plugin.fuzz;

/**
 *
 * @author  rogan
 */
public interface FuzzSource {
    
    String getDescription();
    
    int size();
    
    void reset();
    
    boolean hasNext();
    
    Object current();
    
    void increment();
    
    FuzzSource newInstance();
    
}
