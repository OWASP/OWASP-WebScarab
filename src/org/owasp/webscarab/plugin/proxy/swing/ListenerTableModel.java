/*
 * ListenerTableModel.java
 *
 * Created on August 31, 2003, 11:59 PM
 */

package org.owasp.webscarab.plugin.proxy.swing;

import java.util.ArrayList;

import javax.swing.table.AbstractTableModel;

import org.owasp.webscarab.plugin.proxy.Proxy;

/**
 *
 * @author  rdawes
 */
public class ListenerTableModel extends AbstractTableModel {

    private Proxy _proxy;
    private ArrayList _listeners = new ArrayList();
    
    protected String [] columnNames = {
        "Address", "Port", "Base URL", "Simulated network", "Uses plugins"
    };
    
    protected Class[] columnClass = {
        String.class, Integer.class, String.class, String.class, Boolean.class
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
        return _listeners.size();
    }

    public synchronized Object getValueAt(int row, int column) {
        if (row<0 || row >= _listeners.size()) {
            System.err.println("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            return null;
        }
        String key = (String) _listeners.get(row);
        if (column <= columnNames.length) {
            switch (column) {
                case 0: return _proxy.getAddress(key);
                case 1: return new Integer(_proxy.getPort(key));
                case 2: return _proxy.getBase(key);
                case 3: return _proxy.getSimulator(key);
                case 4: return new Boolean(_proxy.usesPlugins(key));
                default: return null;
            }
        } else {
            System.err.println("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            return null;
        }
    }
    
    public String getKey(int index) {
        return (String) _listeners.get(index);
    }
    
    public void proxyRemoved(String key) {
        int index = _listeners.indexOf(key);
        if (index > -1) {
            _listeners.remove(index);
            fireTableRowsDeleted(index, index);
        }
    }
    
    public void proxyAdded(String key) {
        int index = _listeners.indexOf(key);
        if (index == -1) {
            _listeners.add(key);
            fireTableRowsInserted(_listeners.size(), _listeners.size());
        }
    }
    
}
