/*
 * ContentFuzzer.java
 *
 * Created on 06 February 2005, 08:59
 */

package org.owasp.webscarab.plugin.fuzz;

/**
 *
 * @author  rogan
 */
public interface RequestFuzzer {
    
    String getContentType();
    
    byte[] getNextContent();
    
}
