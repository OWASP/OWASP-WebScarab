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
 * ListComboBoxModel.java
 *
 * Created on October 1, 2003, 11:15 PM
 */

package org.owasp.webscarab.util.swing;

import javax.swing.AbstractListModel;
import javax.swing.ListModel;
import javax.swing.ComboBoxModel;

import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */
public class ListComboBoxModel extends AbstractListModel implements ComboBoxModel {
    
    ListModel _list;
    Object _selected = null;
    
    Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of ListComboBoxModel */
    public ListComboBoxModel(ListModel list) {
        _list = list;
        _list.addListDataListener(new MyListener());
    }
    
    public Object getElementAt(int index) {
        return _list.getElementAt(index);
    }
    
    public Object getSelectedItem() {
        return _selected;
    }
    
    public int getSize() {
        return _list.getSize();
    }
    
    public void setSelectedItem(Object anItem) {
        _selected = anItem;
    }
    
    private class MyListener implements ListDataListener {
        
        public void contentsChanged(ListDataEvent e) {
            fireContentsChanged(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
        public void intervalAdded(ListDataEvent e) {
            fireIntervalAdded(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
        public void intervalRemoved(ListDataEvent e) {
            fireIntervalRemoved(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
    }
}
