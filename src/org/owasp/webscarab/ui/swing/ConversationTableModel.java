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
 * ConversationTableModel.java
 *
 * Created on June 21, 2004, 6:05 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.SiteModelAdapter;
import org.owasp.webscarab.model.SiteModelEvent;

import org.owasp.webscarab.util.swing.ExtensibleTableModel;

import javax.swing.table.AbstractTableModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationTableModel extends ExtensibleTableModel {
    
    protected SiteModel _model = null;
    protected HttpUrl _url = null;
    
    private Listener _listener = new Listener();
    
    protected Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationTableModel(SiteModel model) {
        _model = model;
        _model.addModelListener(_listener);
    }
    
    public void setUrl(HttpUrl url) {
        _url = url;
        fireTableDataChanged();
    }
    
    public Object getKeyAt(int row) {
        return _model.getConversationAt(_url, row);
    }
    
    public int indexOfKey(Object key) {
        return _model.getIndexOfConversation(_url, (ConversationID) key);
    }
    
    public int getRowCount() {
        if (_model == null) return 0;
        return _model.getConversationCount(_url);
    }
    
    public int getColumnCount() {
        return super.getColumnCount()+1;
    }
    
    public Object getValueAt(int row, int column) {
        Object key = getKeyAt(row);
        if (column == 0) return key;
        return super.getValueAt(key, column-1);
    }
    
    /**
     * Returns the name of the column at <code>column</code>.  This is used
     * to initialize the table's column header name.  Note: this name does
     * not need to be unique; two columns in a table can have the same name.
     *
     * @param	column the index of the column
     * @return  the name of the column
     */
    public String getColumnName(int column) {
        if (column == 0) return "ID";
        return super.getColumnName(column-1);
    }
    
    /**
     * Returns the most specific superclass for all the cell values
     * in the column.  This is used by the <code>JTable</code> to set up a
     * default renderer and editor for the column.
     *
     * @param column the index of the column
     * @return the common ancestor class of the object values in the model.
     */
    public Class getColumnClass(int column) {
        if (column == 0) return ConversationID.class;
        return super.getColumnClass(column-1);
    }
    
    protected void addedConversation(SiteModelEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = indexOfKey(id);
        fireTableRowsInserted(row, row);
    }
    
    protected void removedConversation(SiteModelEvent evt) {
        fireTableDataChanged();
    }
    
    protected void changedConversations(SiteModelEvent evt) {
        fireTableDataChanged();
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(final SiteModelEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                addedConversation(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            addedConversation(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + ": " + e);
                }
            }
        }
        
        public void conversationRemoved(final SiteModelEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                removedConversation(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            removedConversation(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + ": " + e);
                }
            }
        }
        
        public void dataChanged(final SiteModelEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                changedConversations(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            changedConversations(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + ": " + e);
                }
            }
        }
        
    }
    
}
