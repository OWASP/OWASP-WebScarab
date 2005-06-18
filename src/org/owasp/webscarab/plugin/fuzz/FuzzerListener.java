/*
 * FuzzListener.java
 *
 * Created on 06 February 2005, 08:42
 */

package org.owasp.webscarab.plugin.fuzz;

import java.util.EventListener;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public interface FuzzerListener extends EventListener {
    
    void fuzzHeaderAdded(FuzzerEvent evt);
    
    void fuzzHeaderChanged(FuzzerEvent evt);
    
    void fuzzHeaderRemoved(FuzzerEvent evt);
    
    void fuzzParameterAdded(FuzzerEvent evt);
    
    void fuzzParameterChanged(FuzzerEvent evt);
    
    void fuzzParameterRemoved(FuzzerEvent evt);
    
}
