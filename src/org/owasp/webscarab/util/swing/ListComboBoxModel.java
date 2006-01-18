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
        if (_selected == null && anItem == null) return;
        if (_selected == null && anItem != null ||
                _selected != null && anItem == null ||
                ! _selected.equals(anItem)) {
            _selected = anItem;
            fireContentsChanged(this, -1, -1);
        }
        
    }
    
    private class MyListener implements ListDataListener {
        
        public void contentsChanged(ListDataEvent e) {
            fireContentsChanged(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
            setSelectedItem(null);
        }
        
        public void intervalAdded(ListDataEvent e) {
            fireIntervalAdded(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
        public void intervalRemoved(ListDataEvent e) {
            fireIntervalRemoved(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
            // we should notify listeners if the selected item has been removed
            if (_selected == null) return;
            int size = getSize();
            for (int i=0; i<size; i++) {
                Object item = getElementAt(i);
                if (item != null && item.equals(_selected)) return;
            }
            // we haven't found it, it's been removed
            setSelectedItem(null);
        }
        
    }
    
    public static void main(String[] argList) {
        javax.swing.JFrame top = new javax.swing.JFrame("ListComboBoxTest");
        final javax.swing.DefaultListModel dlm = new javax.swing.DefaultListModel();
        final ListComboBoxModel lcbm = new ListComboBoxModel(dlm);
        lcbm.addListDataListener(new ListDataListener() {
            public void intervalRemoved(ListDataEvent evt) {
                System.err.println("Interval Removed : " + evt);
            }
            public void intervalAdded(ListDataEvent evt) {
                System.err.println("Interval Added : " + evt);
            }
            public void contentsChanged(ListDataEvent evt) {
                System.err.println("ContentsChanged: " + evt);
            }
        });
        dlm.addElement("a");
        dlm.addElement("b");
        dlm.addElement("c");
        dlm.addElement("d");
        javax.swing.JComboBox jcb = new javax.swing.JComboBox(lcbm);
        jcb.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.err.println("Event : " + evt.paramString());
            }
        });
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        top.getContentPane().add(jcb, java.awt.BorderLayout.NORTH);
        javax.swing.JButton clear = new javax.swing.JButton("CLEAR");
        top.getContentPane().add(clear, java.awt.BorderLayout.SOUTH);
        clear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dlm.clear();
                System.err.println("DLM size = " + dlm.size());
                System.err.println("Selected item = " + lcbm.getSelectedItem());
            }
        });
        javax.swing.JButton select = new javax.swing.JButton("SELECT");
        top.getContentPane().add(select, java.awt.BorderLayout.WEST);
        select.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                lcbm.setSelectedItem(lcbm.getElementAt(0));
                System.err.println("Selected " + lcbm.getSelectedItem());
            }
        });
        // top.setBounds(100,100,600,400);
        top.pack();
        top.setVisible(true);
        
    }
    
}
