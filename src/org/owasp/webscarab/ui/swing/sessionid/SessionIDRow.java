/*
 * IDRow.java
 *
 * Created on March 31, 2004, 3:49 PM
 */

package org.owasp.webscarab.ui.swing.sessionid;

import org.owasp.webscarab.plugin.sessionid.SessionID;

import org.owasp.webscarab.util.swing.TableRow;

import java.util.Date;
import java.math.BigInteger;

/**
 *
 * @author  rdawes
 */
public class SessionIDRow implements TableRow {
    
    private String[] _columnNames = new String[] { "Date", "Value", "Integer" };
    
    /** Creates a new instance of IDRow */
    public SessionIDRow() {
    }
    
    public Class getColumnClass(int column) {
        switch (column) {
            case 0: return Date.class;
            case 1: return String.class;
            case 2: return BigInteger.class;
        }
        return null;
    }
    
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    public String getColumnName(int column) {
        return _columnNames[column];
    }
    
    public Object getValueAt(Object object, int column) {
        if (object instanceof SessionID) {
            SessionID id = (SessionID) object;
            switch (column) {
                case 0: return id.getDate();
                case 1: return id.getValue();
                case 2: return id.getIntValue();
            }
        }
        return "Invalid underlying object";
    }
    
    public boolean isFieldEditable(Object object, int column) {
        return false;
    }
    
    public void setValueAt(Object aValue, Object object, int column) {
    }
    
}
