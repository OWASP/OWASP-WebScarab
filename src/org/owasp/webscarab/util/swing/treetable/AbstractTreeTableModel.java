package org.owasp.webscarab.util.swing.treetable;

import org.owasp.webscarab.util.swing.AbstractTreeModel;
 
public abstract class AbstractTreeTableModel extends AbstractTreeModel implements TreeTableModel {
    
    //
    // Default impelmentations for methods in the TreeTableModel interface. 
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
