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
 * DefaultTreeTableModel.java
 *
 * Created on 15 November 2003, 06:22
 */

package org.owasp.webscarab.util.swing.treetable;

import javax.swing.tree.DefaultTreeModel;

import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.MutableTreeNode;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;

import java.io.Serializable;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import java.util.Vector;

/**
 * A simple treetable data model based on DefaultTreeModel. This 
 * implementation merely displays the tree in a single column. Subclass the 
 * getColumnCount and getValueAt methods to change this behaviour
 * <p>
 * <strong>Warning:</strong>
 * Serialized objects of this class will not be compatible with
 * future Swing releases. The current serialization support is
 * appropriate for short term storage or RMI between applications running
 * the same version of Swing.  As of 1.4, support for long term storage
 * of all JavaBeans<sup><font size="-2">TM</font></sup>
 * has been added to the <code>java.beans</code> package.
 * Please see {@link java.beans.XMLEncoder}.
 *
 * @author Rogan Dawes
 */
public class DefaultTreeTableModel extends DefaultTreeModel implements TreeTableModel {
    
    /**
      * Creates a tree in which any node can have children.
      *
      * @param root a TreeNode object that is the root of the tree
      * @see #DefaultTreeModel(TreeNode, boolean)
      */
     public DefaultTreeTableModel(TreeNode root) {
        this(root, false);
    }

    /**
      * Creates a tree specifying whether any node can have children,
      * or whether only certain nodes can have children.
      *
      * @param root a TreeNode object that is the root of the tree
      * @param asksAllowsChildren a boolean, false if any node can
      *        have children, true if each node is asked to see if
      *        it can have children
      * @see #asksAllowsChildren
      */
    public DefaultTreeTableModel(TreeNode root, boolean asksAllowsChildren) {
        super(root, asksAllowsChildren);
    }
    
    // TreeTable specific methods
    
    /**
     * Returns the number of available columns.
     */
    public int getColumnCount() {
        return 1;
    }

    /**
     * Returns the name for column number <code>column</code>.
     */
    public String getColumnName(int column) {
        return "A";
    }

    /**
     * Returns the type for column number <code>column</code>.
     */
    public Class getColumnClass(int column) {
        return column == 0 ? TreeTableModel.class : Object.class;
    }

    /**
     * Returns the value to be displayed for node <code>node</code>, 
     * at column number <code>column</code>.
     */
    public Object getValueAt(Object node, int column) {
        return column == 0 ? node : "Override getValueAt!!";
    }

   /** By default, make the column with the Tree in it the only editable one. 
    *  Making this column editable causes the JTable to forward mouse 
    *  and keyboard events in the Tree column to the underlying JTree. 
    */ 
    public boolean isCellEditable(Object node, int column) { 
         return getColumnClass(column) == TreeTableModel.class; 
    }


    /**
     * Sets the value for node <code>node</code>, 
     * at column number <code>column</code>.
     */
    public void setValueAt(Object aValue, Object node, int column){
    }

}
