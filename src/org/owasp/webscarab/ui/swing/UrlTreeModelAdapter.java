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
 * SiteTreeModelAdapter.java
 *
 * Created on August 27, 2004, 4:19 AM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import org.owasp.webscarab.util.swing.AbstractTreeModel;

import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.UrlModel;
import org.owasp.webscarab.model.UrlListener;
import org.owasp.webscarab.model.UrlEvent;

import java.util.Set;
import java.util.HashSet;
import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class UrlTreeModelAdapter extends AbstractTreeModel {
    
    protected UrlModel _model;
    private Listener _listener = new Listener();
    
    protected Logger _logger = Logger.getLogger(getClass().getName());
    
    private Object _root = new String("RooT");
    
    public UrlTreeModelAdapter(UrlModel model) {
        _model = model;
        _model.addUrlListener(_listener);
    }
    
    public Object getRoot() {
        return _root;
    }
    
    public Object getChild(Object parent, int index) {
        if (_model == null) throw new NullPointerException("Getting a child when the model is null!");
        if (parent == getRoot()) parent = null;
        return _model.getChildAt((HttpUrl) parent, index);
    }
    
    public int getChildCount(Object parent) {
        if (_model == null) return 0;
        if (parent == getRoot()) parent = null;
        return _model.getChildCount((HttpUrl) parent);
    }
    
    public boolean isLeaf(Object node) {
        if (node == getRoot()) return false;
        HttpUrl url = (HttpUrl) node;
        if (url.getParameters() != null) return true;
        if (url.getPath().endsWith("/")) return false;
        return getChildCount(url) == 0;
    }
    
    public void valueForPathChanged(TreePath path, Object newValue) {
        // we do not support editing
    }
    
    protected TreePath urlTreePath(HttpUrl url) {
        Object root = getRoot();
        if (url == null || url == root) {
            return new TreePath(root);
        } else {
            Object[] urlPath = url.getUrlHierarchy();
            Object[] path = new Object[urlPath.length+1];
            path[0] = root;
            System.arraycopy(urlPath, 0, path, 1, urlPath.length);
            return new TreePath(path);
        }
    }
    
    private class Listener implements UrlListener {
        
        public void urlAdded(final UrlEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                HttpUrl url = evt.getUrl();
                HttpUrl parent = url.getParentUrl();
                int index = getIndexOfChild(parent, url);
                fireChildAdded(urlTreePath(parent), index, url);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            urlAdded(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + " " + e);
                    e.getCause().printStackTrace();
                }
            }
        }
        
        public void urlChanged(final UrlEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                HttpUrl url = evt.getUrl();
                HttpUrl parent = url.getParentUrl();
                int index = getIndexOfChild(parent, url);
                fireChildChanged(urlTreePath(parent), index, url);
            } else {
                if (true) return;
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            urlChanged(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + " " + e);
                    e.getCause().printStackTrace();
                }
            }
        }
        
        public void urlRemoved(final UrlEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                HttpUrl url = evt.getUrl();
                HttpUrl parent = url.getParentUrl();
                int pos = 0;
                int count = getChildCount(parent);
                for (int i=0; i<count; i++) {
                    HttpUrl sibling = (HttpUrl) getChild(parent, i);
                    if (url.compareTo(sibling)<0) {
                        break;
                    } else {
                        pos++;
                    }
                }
                fireChildRemoved(urlTreePath(parent), pos, url);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            urlRemoved(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing " + evt + " " + e);
                    e.getCause().printStackTrace();
                }
            }
        }
        
        public void urlsChanged() {
            if (SwingUtilities.isEventDispatchThread()) {
                fireStructureChanged();
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            urlsChanged();
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception processing event: " + e);
                    e.getCause().printStackTrace();
                }
            }
        }
        
    }
}
