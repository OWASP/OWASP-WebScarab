/*
 * URLModel.java
 *
 * Created on September 3, 2003, 9:33 PM
 */

package org.owasp.webscarab.model;

import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;

import javax.swing.event.EventListenerList;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;

import java.util.TreeMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import java.util.Enumeration;

/**
 *
 * @author  rdawes
 */
public class URLTreeModel implements TreeModel {
    
    private int _count = 0;
    private TreeMap _treemap;
    private URLNode _root;
    
    /** Listeners. */
    protected EventListenerList listenerList = new EventListenerList();

    /** Creates a new instance of URLModel */
    public URLTreeModel() {
        _treemap = new TreeMap();
        _root = new URLNode(null, "", false);
        _treemap.put("", _root);
    }
    
    public void add(String url) {
        synchronized (_treemap) {
            URLNode node = (URLNode) _treemap.get(url);
            if (node != null && node.isImplied()) {
                node.setImplied(false);
                fireTreeNodesChanged(node, null, null);
                return;
            }
            String[] path = urlPath(url);
            URLNode parent = (URLNode) getRoot();
            int index = 0;
            for (int i=1; i<path.length-1; i++) {
                node = (URLNode) _treemap.get(path[i]);
                if (node == null) {
                    node = new URLNode(parent, path[i], true);
                    _treemap.put(path[i], node);
                    index = parent.addChild(node);
                    if (index >= 0) {
                        fireTreeNodesInserted(parent, new int[] {index}, parent.getChildren());
                    }
                }
                parent = node;
            }

            node = new URLNode(parent, url, false);
            _treemap.put(url, node);
            index = parent.addChild(node);
            if (index >= 0) {
                fireTreeNodesInserted(parent, new int[] {index}, parent.getChildren());
            }
        }
    }
    
    public void clear() {
        synchronized (_treemap) {
            _treemap.clear();
            _root = new URLNode(null, "", false);
            _treemap.put("", _root);
            fireTreeStructureChanged(getRoot());
        }
    }
    
    public void remove(String url) {
        synchronized (_treemap) {
            URLNode node = (URLNode) _treemap.get(url);
            if (node.getChildCount() == 0) {
                remove(node);
                return;
            }
            if (!node.isImplied()) {
                node.setImplied(true);
                fireTreeNodesChanged(node, null, null);
            }
        }
    }
    
    public void remove(URLNode node) {
        synchronized (_treemap) {
            URLNode parent = (URLNode) node.getParent();
            int index = parent.removeChild(node);
            _treemap.remove(node.getURL());
            if (parent != getRoot() && parent.isImplied() && parent.getChildCount() == 0) {
                remove(parent);
            } else {
                fireTreeNodesRemoved(parent, new int[] {index}, parent.getChildren());
            }
        }
    }
    
    
    public Object getChild(Object parent, int index) {
        return ((URLNode)parent).getChildAt(index);
    }
    
    public int getChildCount(Object parent) {
        return ((URLNode)parent).getChildCount();
    }
    
    public int getIndexOfChild(Object parent, Object child) {
        return ((URLNode)parent).getIndex((URLNode) child);
    }
    
    public Object getRoot() {
        return _root;
    }
    
    public boolean isLeaf(Object node) {
        return ((URLNode)node).isLeaf();
    }
    
    /**
     * Adds a listener for the TreeModelEvent posted after the tree changes.
     *
     * @see     #removeTreeModelListener
     * @param   l       the listener to add
     */
    public void addTreeModelListener(TreeModelListener l) {
        listenerList.add(TreeModelListener.class, l);
    }

    /**
     * Removes a listener previously added with <B>addTreeModelListener()</B>.
     *
     * @see     #addTreeModelListener
     * @param   l       the listener to remove
     */  
    public void removeTreeModelListener(TreeModelListener l) {
        listenerList.remove(TreeModelListener.class, l);
    }
    
    public void valueForPathChanged(javax.swing.tree.TreePath path, Object newValue) {
        System.out.println("valueForPathChanged(" + path + ", " + newValue + ")");
    }
    
    /**
     * Notifies all listeners that have registered interest for
     * notification on this event type.  The event instance 
     * is lazily created using the parameters passed into 
     * the fire method.
     *
     * @param source the node being changed
     * @param childIndices the indices of the changed elements
     * @param children the changed elements
     * @see EventListenerList
     */
    protected void fireTreeNodesChanged(Object source,
                                        int[] childIndices, 
                                        Object[] children) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null) {
                    Object[] path = treePath(((URLNode)source).getURL());
                    
                    e = new TreeModelEvent(source, path, 
                                           childIndices, children);
                }
                ((TreeModelListener)listeners[i+1]).treeNodesChanged(e);
            }          
        }
    }

    /**
     * Notifies all listeners that have registered interest for
     * notification on this event type.  The event instance 
     * is lazily created using the parameters passed into 
     * the fire method.
     *
     * @param source the node where new elements are being inserted
     * @param childIndices the indices of the new elements
     * @param children the new elements
     * @see EventListenerList
     */
    protected void fireTreeNodesInserted(Object source, 
                                        int[] childIndices, 
                                        Object[] children) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null) {
                    Object[] path = treePath(((URLNode)source).getURL());
                    e = new TreeModelEvent(source, path, 
                                           childIndices, children);
                }
                ((TreeModelListener)listeners[i+1]).treeNodesInserted(e);
            }          
        }
    }

    /**
     * Notifies all listeners that have registered interest for
     * notification on this event type.  The event instance 
     * is lazily created using the parameters passed into 
     * the fire method.
     *
     * @param source the node where elements are being removed
     * @param childIndices the indices of the removed elements
     * @param children the removed elements
     * @see EventListenerList
     */
    protected void fireTreeNodesRemoved(Object source, 
                                        int[] childIndices, 
                                        Object[] children) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null) {
                    Object[] path = treePath(((URLNode)source).getURL());
                    e = new TreeModelEvent(source, path, 
                                           childIndices, children);
                }
                ((TreeModelListener)listeners[i+1]).treeNodesRemoved(e);
            }          
        }
    }

    /**
     * Notifies all listeners that have registered interest for
     * notification on this event type.  The event instance 
     * is lazily created using the parameters passed into 
     * the fire method.
     *
     * @param source the node where the tree model has changed
     * @param childIndices the indices of the affected elements
     * @param children the affected elements
     * @see EventListenerList
     */
    protected void fireTreeStructureChanged(Object source, 
                                        int[] childIndices, 
                                        Object[] children) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null) {
                    Object[] path = treePath(((URLNode)source).getURL());
                    e = new TreeModelEvent(source, path, 
                                           childIndices, children);
                }
                ((TreeModelListener)listeners[i+1]).treeStructureChanged(e);
            }          
        }
    }

    /*
     * Notifies all listeners that have registered interest for
     * notification on this event type.  The event instance 
     * is lazily created using the parameters passed into 
     * the fire method.
     *
     * @param source the node where the tree model has changed
     * @see EventListenerList
     */
    private void fireTreeStructureChanged(Object source) {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null) {
                    Object[] path = treePath(((URLNode)source).getURL());
                    e = new TreeModelEvent(source, path);
                }
                ((TreeModelListener)listeners[i+1]).treeStructureChanged(e);
            }
        }
    }

    private String[] urlSegments(String url) {
        if (url.equals("")) {
            return new String[0];
        }
        Vector parts = new Vector();
        String shp = url.substring(0,url.indexOf("/",9)+1);
        parts.add(shp);
        int start = shp.length();
        int slash;
        String part;
        while ((slash = url.indexOf("/",start)) > -1) {
            parts.add(url.substring(start,slash+1));
            start = slash + 1;
        }
        if (start < url.length()) {
            parts.add(url.substring(start));
        }
        return (String[]) parts.toArray(new String[] {""});
    }
    
    private String[] urlPath(String url) {
        String[] segments = urlSegments(url);
        String[] path = new String[segments.length+1];
        path[0] = "";
        for (int i=1; i<path.length; i++) {
            path[i] = path[i-1] + segments[i-1];
        }
        return path;
    }
    
    private URLNode[] treePath(String url) {
        // System.out.println("Getting treePath for '" + url + "'");
        String[] urlpath = urlPath(url);
        URLNode[] path = new URLNode[urlpath.length];
        for (int i=0; i<urlpath.length; i++) {
            path[i] = (URLNode) _treemap.get(urlpath[i]);
            if (path[i] == null) {
                System.err.println("Error getting the Node for " + urlpath[i]);
            }
        }
        return path;
    }
    
    public class URLNode implements TreeNode {
        
        private String _url;
        private String _lastSegment = "";
        private boolean _implied;
        private URLNode _parent;
        private Vector _children = new Vector();
        
        protected URLNode(URLNode parent, String url, boolean implied) {
            _parent = parent;
            _url = url;
            _implied = implied;
            String[] segments = urlSegments(url);
            if (segments.length>0) {
                _lastSegment = segments[segments.length-1];
            }
        }
        
        public int addChild(Object child) {
            if (_children.size() == 0) {
                _children.add(child);
                return 0;
            }
            Object last = _children.get(_children.size()-1);
            if (last.toString().compareTo(child.toString()) < 0) {
                _children.add(child);
                return _children.size()-1;
            }
            for (int i=0; i<_children.size(); i++) {
                if (child.toString().compareTo(_children.get(i).toString()) < 0) {
                    _children.insertElementAt(child, i);
                    return i;
                }
            }
            return -1;
        }
        
        public int removeChild(Object child) {
            if (_children.size() == 0) {
                return -1;
            }
            int index = _children.indexOf(child);
            if (index >= 0) {
                _children.remove(index);
            }
            return index;
        }
        
        public Object[] getChildren() {
            return _children.toArray();
        }
        
        public Enumeration children() {
            return _children.elements();
        }
        
        public boolean getAllowsChildren() {
            return (_lastSegment.equals("") || _lastSegment.endsWith("/"));
        }
        
        public TreeNode getChildAt(int childIndex) {
            return (TreeNode) _children.get(childIndex);
        }
        
        public int getChildCount() {
            return _children.size();
        }
        
        public int getIndex(TreeNode node) {
            return _children.indexOf(node);
        }
        
        public TreeNode getParent() {
            return _parent;
        }
        
        public boolean isLeaf() {
            return ! getAllowsChildren();
        }
        
        public boolean isImplied() {
            return _implied;
        }
        
        public void setImplied(boolean implied) {
            _implied = implied;
        }
        
        public String toString() {
            return _lastSegment;
        }
        
        public String getURL() {
            return _url;
        }
    }
    
}
