/*
 * ListenerTableModel.java
 *
 * Created on August 31, 2003, 11:59 PM
 */

package org.owasp.webscarab.ui.swing.proxy;

import javax.swing.table.AbstractTableModel;
import org.owasp.webscarab.plugin.proxy.Proxy;

/**
 *
 * @author  rdawes
 */
public class ListenerTableModel extends AbstractTableModel {

    private Proxy _proxy;
    
    protected String [] columnNames = {
        "Address", "Port", "Base URL", "Uses plugins"
    };
    
    protected Class[] columnClass = {
        String.class, Integer.class, String.class, Boolean.class
    };
    
    public ListenerTableModel(Proxy proxy) {
        _proxy = proxy;
    }

    public String getColumnName(int column) {
        if (column < columnNames.length) {
            return columnNames[column];
        }
        return "";
    }
    
    public Class getColumnClass(int column) {
        return columnClass[column];
    }
    
    public synchronized int getColumnCount() {
        return columnNames.length;
    }

    public synchronized int getRowCount() {
        return _proxy.getProxies().length;
    }

    public synchronized Object getValueAt(int row, int column) {
        String[] keys = _proxy.getProxies();
        if (row<0 || row >= keys.length) {
            System.err.println("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            return null;
        }
        if (column <= columnNames.length) {
            switch (column) {
                case 0: return _proxy.getAddress(keys[row]);
                case 1: return new Integer(_proxy.getPort(keys[row]));
                case 2: return _proxy.getBase(keys[row]);
                case 3: return new Boolean(_proxy.getPlugins(keys[row]));
                default: return null;
            }
        } else {
            System.err.println("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            return null;
        }
    }
    
}
