/*
 * Copyright (c) 2002 owasp.org.
 * This file is part of WebScarab.
 * WebScarab is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * WebScarab is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The valid license text for this file can be retrieved with
 * the call:   java -cp owasp.jar org.owasp.webscarab.LICENSE
 * 
 * If you are not able to view the LICENSE that way, which should
 * always be possible within a valid and working WebScarab release,
 * please write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.owasp.webscarab.ui.swing.spider;

import javax.swing.Icon;
import java.awt.event.ActionListener;

/**
 * An interface which defines how a URLTreeNode should behave.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:21 $
 */
public interface Behaviour extends ActionListener{
    
    /**
     * Set the node that this behaviour relates to.
     * 
     * @param node the node that this behaviour relates to, can be null
     */
    void setNode(URLTreeNode node);
    
    /**
     * Return the Icon to use for a leaf node.
     * 
     * @returns Icon to represent a leaf node.
     */
    Icon getLeafIcon();
    
    /**
     * Return the Icon to use for an open non-leaf node.
     * 
     * @returns Icon to represent an open non-leaf node.
     */
    Icon getOpenIcon();
    
    /**
     * Return the Icon to use for a closed non-leaf node.
     * 
     * @returns Icon to represent a closed non-leaf node.
     */
    Icon getClosedIcon();
}
