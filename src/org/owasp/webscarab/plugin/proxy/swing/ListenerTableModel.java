/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

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
        "Address", "Port", "Base URL", "Simulated network", "Primary"
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
                case 4: return new Boolean(_proxy.isPrimaryProxy(key));
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
