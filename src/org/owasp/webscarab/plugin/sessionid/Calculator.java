/*
 * Calculator.java
 *
 * Created on August 9, 2004, 8:10 PM
 */

package org.owasp.webscarab.plugin.sessionid;

import java.math.BigInteger;

/**
 *
 * @author  knoppix
 */
public interface Calculator {

    void reset();
    
    boolean add(SessionID id);
    
    BigInteger calculate(SessionID id);
    
}
