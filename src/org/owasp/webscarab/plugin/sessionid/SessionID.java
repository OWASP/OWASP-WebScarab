/*
 * SessionID.java
 *
 * Created on 16 November 2003, 07:29
 */

package org.owasp.webscarab.plugin.sessionid;

import java.util.Date;

/**
 *
 * @author  rdawes
 */
public class SessionID implements Comparable {
    
    private Date _date;
    private String _value;
    
    /** Creates a new instance of SessionID */
    public SessionID(Date date, String value) {
        _date = date;
        _value = value;
    }
    
    public SessionID(String line) {
        int sep = line.indexOf(":");
        String time = line.substring(0, sep);
        _date = new Date(Long.parseLong(time));
        _value = line.substring(sep+2);
    }
    
    public Date getDate() {
        return _date;
    }
    
    public String getValue() {
        return _value;
    }
    
    public int compareTo(Object o) {
        if (o == null) return -1;
        if (!(o instanceof SessionID)) return -1;
        return _date.compareTo(((SessionID)o).getDate());
    }
    
    public String toString() {
        return _date.getTime() + ": " + _value;
    }
    
}
