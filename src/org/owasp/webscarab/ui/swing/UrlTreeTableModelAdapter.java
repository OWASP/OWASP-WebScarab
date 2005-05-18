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

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.UrlModel;
import org.owasp.webscarab.model.HttpUrl;

import javax.swing.tree.TreeModel;
import javax.swing.event.TreeModelListener;
import javax.swing.event.TreeModelEvent;

import org.owasp.webscarab.util.swing.treetable.AbstractTreeTableModel;
import org.owasp.webscarab.util.swing.treetable.TreeTableModel;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.ColumnDataListener;
import org.owasp.webscarab.util.swing.ColumnDataEvent;

import java.util.List;
import java.util.ArrayList;

public class UrlTreeTableModelAdapter extends UrlTreeModelAdapter implements TreeTableModel {
    
    private List _columns = new ArrayList();
    private ColumnDataListener _columnListener;
    
    public UrlTreeTableModelAdapter(UrlModel model) {
        super(model);
        createListener();
    }
    
    private void createListener() {
        _columnListener = new ColumnDataListener() {
            public void dataChanged(ColumnDataEvent cde) {
                Object column = cde.getSource();
                int col = _columns.indexOf(column);
                if (col < 0) return;
                Object key = cde.getKey();
                if (key == null) {
                    fireStructureChanged();
                } else {
                    HttpUrl url = (HttpUrl) key;
                    firePathChanged(urlTreePath(url));
                }
            }
        };
    }
    
    public void addColumn(ColumnDataModel column) {
        _columns.add(column);
        column.addColumnDataListener(_columnListener);
        fireStructureChanged();
    }
    
    public void removeColumn(ColumnDataModel column) {
        int index = _columns.indexOf(column);
        if (index < 0) return;
        column.removeColumnDataListener(_columnListener);
        _columns.remove(index);
        fireStructureChanged();
    }
    
    //
    //  The TreeTableNode interface.
    //
    
    /**
     * Returns the number of columns.
     */
    public int getColumnCount() {
        return _columns.size()+1;
    }
    
    /**
     * Returns the name for a particular column.
     */
    public String getColumnName(int column) {
        if (column == 0) return "Url";
        return ((ColumnDataModel) _columns.get(column-1)).getColumnName();
    }
    
    /**
     * Returns the class for the particular column.
     */
    public Class getColumnClass(int column) {
        if (column == 0) return TreeTableModel.class;
        return ((ColumnDataModel) _columns.get(column-1)).getColumnClass();
    }
    
    /**
     * Returns the value of the particular column.
     */
    public Object getValueAt(Object node, int column) {
        if (! (node instanceof HttpUrl)) return null;
        HttpUrl url = (HttpUrl) node;
        if (column == 0) return url;
        return ((ColumnDataModel) _columns.get(column-1)).getValue(url);
    }
    
    /** By default, make the column with the Tree in it the only editable one.
     *  Making this column editable causes the JTable to forward mouse
     *  and keyboard events in the Tree column to the underlying JTree.
     */
    public boolean isCellEditable(Object node, int column) {
        return getColumnClass(column) == TreeTableModel.class;
    }
    
    public void setValueAt(Object aValue, Object node, int column) {}
    
}
