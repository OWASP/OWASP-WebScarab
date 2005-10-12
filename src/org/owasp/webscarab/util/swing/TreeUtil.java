/*
 * TreeUtil.java
 *
 * Created on 11 October 2005, 09:34
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.util.swing;

import javax.swing.JTree;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

/**
 *
 * @author rdawes
 */
public class TreeUtil {
    
    /** Creates a new instance of TreeUtil */
    private TreeUtil() {
    }
    
    public static void expandAll(JTree tree, boolean expand) {
        TreeModel model = tree.getModel();
        
        // Traverse tree from root
        expandAll(tree, new TreePath(tree.getModel().getRoot()), expand);
    }
    
    private static void expandAll(JTree tree, TreePath path, boolean expand) {
        Object parent = path.getLastPathComponent();
        int childCount = tree.getModel().getChildCount(parent);
        for (int i=0; i<childCount; i++) {
            Object child = tree.getModel().getChild(parent, i);
            TreePath childPath = path.pathByAddingChild(child);
            expandAll(tree, childPath, expand);
        }
        
        // Expansion or collapse must be done bottom-up
        if (expand) {
            tree.expandPath(path);
        } else {
            tree.collapsePath(path);
        }
    }
    
}
