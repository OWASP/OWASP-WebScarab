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
 * UrlTreeRenderer.java
 *
 * Created on August 8, 2004, 5:16 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.HttpUrl;

import java.awt.Component;
import javax.swing.JTree;
import javax.swing.JLabel;
import javax.swing.tree.DefaultTreeCellRenderer;

/**
 *
 * @author  knoppix
 */
public class UrlTreeRenderer extends DefaultTreeCellRenderer {
    
    /** Creates a new instance of UrlTreeRenderer */
    public UrlTreeRenderer() {
    }
    
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        Component comp = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
        if (value instanceof HttpUrl && comp instanceof JLabel) {
            JLabel label = (JLabel) comp;
            HttpUrl url = (HttpUrl) value;
            if (url.getParameters() != null) {
                label.setText(url.getParameters());
            } else if (url.getPath().length()>1) {
                String path = url.getPath();
                int pos = path.lastIndexOf("/", path.length()-2);
                label.setText(path.substring(pos+1));
            }
        }
        return comp;
    }
    
}
