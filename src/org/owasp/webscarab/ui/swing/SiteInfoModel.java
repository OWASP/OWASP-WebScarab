package org.owasp.webscarab.ui.swing;

import java.io.IOException;
import java.io.File;
import java.util.Date;
import java.util.Stack;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeModel;
import javax.swing.event.TreeModelListener;
import javax.swing.event.TreeModelEvent;

import org.owasp.webscarab.model.URLTreeModel;
import org.owasp.webscarab.model.URLInfo;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.ui.swing.treetable.AbstractTreeTableModel;
import org.owasp.webscarab.ui.swing.treetable.TreeTableModel;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import java.net.URL;
import java.net.MalformedURLException;

public class SiteInfoModel extends AbstractTreeTableModel {
    
    private TreeModel _treeModel;
    private SiteModel _siteModel;
    
    // Names of the columns.
    static protected String[]  cNames = {"URL", "Method", "Status", "TotalBytes", "Set-Cookie", "Comments", "Scripts"};
    
    // Types of the columns.
    static protected Class[]  cTypes = { TreeTableModel.class,
    String.class, String.class, String.class, 
    Boolean.class, Boolean.class, Boolean.class};
    
    public SiteInfoModel(SiteModel siteModel) {
        super(siteModel.getURLTreeModel().getRoot());
        _siteModel = siteModel;
        _treeModel = _siteModel.getURLTreeModel();
        _treeModel.addTreeModelListener(new TreeModelListener() {
            public void treeNodesChanged(TreeModelEvent e) {
                fireTreeNodesChanged(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());
            }
            public void treeNodesInserted(TreeModelEvent e) {
                fireTreeNodesInserted(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());
            }
            public void treeNodesRemoved(TreeModelEvent e) {
                fireTreeNodesRemoved(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());
            }
            public void treeStructureChanged(TreeModelEvent e) {
                fireTreeStructureChanged(e.getSource(), e.getPath(), e.getChildIndices(), e.getChildren());
            }
        });
    }
    
    //
    // The TreeModel interface
    //
    
    /**
     * Returns the number of children of <code>node</code>.
     */
    public int getChildCount(Object node) {
        return _treeModel.getChildCount(node);
    }
    
    /**
     * Returns the child of <code>node</code> at index <code>i</code>.
     */
    public Object getChild(Object node, int i) {
        return _treeModel.getChild(node,i);
    }
    
    /**
     * Returns true if the passed in object represents a leaf, false
     * otherwise.
     */
    public boolean isLeaf(Object node) {
        return _treeModel.isLeaf(node);
    }
    
    /**
     * calls the underlying tree's updateNode method
     */
//    public TreePath updateNode(URLInfo ui) {
//        return treeModel.updateNode(ui);
//    }
    
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
        URLTreeModel.URLNode fn = (URLTreeModel.URLNode) node;
        URLInfo ui;
        try {
            ui = _siteModel.getURLInfo(new URL(fn.getURL()));
        } catch (MalformedURLException mue) {
            System.err.println("Malformed URL (" + fn.getURL() + ") : " + mue);
            return null;
        }
        
        try {
            if (column == 0) {
                return ui.toString();
            } else if (column < cNames.length) {
                String prop = ui.getProperty(cNames[column].toUpperCase());
                if (prop == null || prop.getClass() == getColumnClass(column)) {
                    return prop;
                } else if (getColumnClass(column) == Boolean.class) {
                    return new Boolean(prop);
                } else {
                    return prop;
                }
            }
        } catch  (SecurityException se) { }
        
        return null;
    }
    
    //
    // Some convenience methods.
    //
    
    protected Object[] getChildren(Object node) {
        URLTreeModel.URLNode fn = (URLTreeModel.URLNode) node;
        Object[] children = new Object[fn.getChildCount()];
        for (int i = 0; i<children.length; i++) {
            children[i] = fn.getChildAt(i);
        }
        return children;
    }
    
    
}
