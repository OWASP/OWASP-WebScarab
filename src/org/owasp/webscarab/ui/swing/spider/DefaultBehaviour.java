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

import java.awt.event.ActionEvent;

import javax.swing.Icon;
import javax.swing.UIManager;

/**
 * A default implementation of the Behaviour interface.
 * 
 * All icon methods return default Icons. The
 * actionPerformed method is empty.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:23 $
 */
public class DefaultBehaviour implements Behaviour {
    /**
     * A shared instance.
     */
    private static DefaultBehaviour _me = null;

    /**
     * Protected constructor. Because this behaviour does nothing
     * a shared instance can be used.
     */
    protected DefaultBehaviour() {
    }
    
    /**
     * Get the shared instance.
     * 
     * @returns the shared instance
     */
    public static DefaultBehaviour getInstance(){
        if (_me == null){
            _me = new DefaultBehaviour();
        }
        return _me;
    }
    
    public void setNode(URLTreeNode node){}
    
    public Icon getLeafIcon(){
        return UIManager.getIcon("Tree.leafIcon");
    }
    
    public Icon getOpenIcon(){
        return UIManager.getIcon("Tree.openIcon");
    }
    
    public Icon getClosedIcon(){
        return UIManager.getIcon("Tree.closedIcon");
    }
    
    public void actionPerformed(ActionEvent evt){}
}
