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

package org.owasp.webscarab.util.swing.treetable;

import org.owasp.webscarab.util.swing.AbstractTreeModel;
 
public abstract class AbstractTreeTableModel extends AbstractTreeModel implements TreeTableModel {
    
    //
    // Default implementations for methods in the TreeTableModel interface. 
    //

    public Class getColumnClass(int column) { 
        return column == 0 ? TreeTableModel.class : Object.class;
    }

   /** By default, make the column with the Tree in it the only editable one. 
    *  Making this column editable causes the JTable to forward mouse 
    *  and keyboard events in the Tree column to the underlying JTree. 
    */ 
    public boolean isCellEditable(Object node, int column) { 
         return getColumnClass(column) == TreeTableModel.class; 
    }

    public void setValueAt(Object aValue, Object node, int column) {}

    // Left to be implemented in the subclass:

    /* 
     *   public int getColumnCount() 
     *   public String getColumnName(Object node, int column)  
     *   public Object getValueAt(Object node, int column) 
     */
}
