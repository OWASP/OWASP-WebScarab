/*
 * SessionID.java
 *
 * Created on 16 November 2003, 07:29
 */

package org.owasp.webscarab.plugin.sessionid;

import java.util.Date;
import java.math.BigInteger;

/**
 *
 * @author  rdawes
 */
public class SessionID {
    
    private Date _date;
    private String _value;
    private BigInteger _intValue = null;
    
    /** Creates a new instance of SessionID */
    public SessionID(Date date, String value) {
        _date = date;
        _value = value;
    }
    
    public Date getDate() {
        return _date;
    }
    
    public String getValue() {
        return _value;
    }
    
    public void setIntValue(BigInteger intValue) {
        _intValue = intValue;
    }
    
    public BigInteger getIntValue() {
        return _intValue;
    }
    
}
