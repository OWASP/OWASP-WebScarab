package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.HttpUrl;

import javax.swing.tree.TreeModel;
import javax.swing.event.TreeModelListener;
import javax.swing.event.TreeModelEvent;

import org.owasp.webscarab.util.swing.treetable.AbstractTreeTableModel;
import org.owasp.webscarab.util.swing.treetable.TreeTableModel;

public class SiteTreeTableModelAdapter extends SiteTreeModelAdapter implements TreeTableModel {
    
    // Names of the columns.
    protected static String[] cNames = {"URL", "Method", "Status", "TotalBytes", "Set-Cookie", "Comments", "Scripts"};
    
    // Types of the columns.
    protected static Class[] cTypes = { TreeTableModel.class,
    String.class, String.class, String.class, 
    Boolean.class, Boolean.class, Boolean.class};
    
    public SiteTreeTableModelAdapter() {
        super();
    }
    
    public SiteTreeTableModelAdapter(SiteModel model) {
        super(model);
    }
    
    //
    //  The TreeTableNode interface.
    //
    
    /**
     * Returns the number of columns.
     */
    public int getColumnCount() {
        return cNames.length;
    }
    
    /**
     * Returns the name for a particular column.
     */
    public String getColumnName(int column) {
        return cNames[column];
    }
    
    /**
     * Returns the class for the particular column.
     */
    public Class getColumnClass(int column) {
        return cTypes[column];
    }
    
    /**
     * Returns the value of the particular column.
     */
    public Object getValueAt(Object node, int column) {
        if (! (node instanceof HttpUrl)) return null;
        HttpUrl url = (HttpUrl) node;
        if (column == 0) {
            return url;
        } else if (column < cNames.length) {
            String prop = cNames[column].toUpperCase();
            String value = _model.getUrlProperty(url,prop);
            if (value == null || getColumnClass(column) == String.class) {
                return value;
            } else if (getColumnClass(column) == Boolean.class) {
                if (! value.equalsIgnoreCase("true") && ! value.equalsIgnoreCase("false")) {
                    return Boolean.TRUE;
                }
                return new Boolean(value);
            } else {
                return value;
            }
        }
        return null;
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
