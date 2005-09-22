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

package org.owasp.webscarab.util.swing;

import org.owasp.webscarab.util.swing.AbstractTreeModel;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.swing.tree.TreePath;

public class DOMTreeModel extends AbstractTreeModel {

    private Node _root;
    
    public DOMTreeModel(Node root) {
        _root = root;
    }
    
    public Object getRoot() {
        return _root;
    }
    
    public int getChildCount(Object parent) {
        NodeList nodes = ((Node) parent).getChildNodes();
        return nodes.getLength();
    }

    public Object getChild(Object parent, int index) {
        NodeList nodes = ((Node) parent).getChildNodes();
        return nodes.item(index);
    }
    
    public boolean isLeaf(Object node) {
        return ((Node)node).getNodeType() != Node.ELEMENT_NODE;
    }
    
    public void valueForPathChanged(TreePath path, Object newValue) {
        // we do not support editing
    }

}

