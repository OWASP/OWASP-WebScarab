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

import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.ActionEvent;

import javax.swing.JTree;

/**
 * A class which takes MouseEvents and fires ActionEvents.
 * 
 * The only MouseEvent we care about is the 'popupTrigger' which
 * is platform dependent.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:22 $
 */
public class ClickMapper extends MouseAdapter {
    private JTree _tree;

    /**
     * Construct a ClickMapper associated with a particular JTree.
     * We add ourselves to the tree's mouse listener list.
     * 
     * @param tree - the JTree which sources MouseEvents to us.
     */
    public ClickMapper(JTree tree) {
        this._tree = tree;
        tree.addMouseListener(this);
    }
    
    public void mousePressed(MouseEvent evt){
        mouseEvt(evt);
    }
    public void mouseReleased(MouseEvent evt){
        mouseEvt(evt);
    }
    
    /**
     * mousePressed and mouseReleased calls are forwarded here for
     * examination. If the event is the popup trigger we fire the
     * ActionEvent to the node of the cell which was clicked.
     */
    private void mouseEvt(MouseEvent evt){
        if (evt.isPopupTrigger()){
            int selRow = _tree.getClosestRowForLocation(evt.getX(), evt.getY());
            Rectangle bounds = _tree.getRowBounds(selRow);
            if (evt.getX() >= bounds.x &&
                evt.getY() >= bounds.y &&
                evt.getX() < bounds.x + bounds.width &&
                evt.getY() < bounds.y + bounds.height)
            {
                _tree.setSelectionRow(selRow);
                URLTreeNode node = (URLTreeNode)_tree.getLastSelectedPathComponent();
                ActionEvent aEvt = new ActionEvent(
                    this,
                    ActionEvent.ACTION_PERFORMED,
                    ""
                );
                node.getBehaviour().actionPerformed(aEvt);
            }
            evt.consume();
        }
    }
}
