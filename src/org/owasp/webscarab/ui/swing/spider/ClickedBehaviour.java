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
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

/**
 * A basic implementation of the Behaviour interface.
 * 
 * The leafIcon is non-default and actionPerformed tells stdErr that
 * the node was clicked.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:22 $
 */
public class ClickedBehaviour extends DefaultBehaviour {
    private static Icon _leafIcon;
    private URLTreeNode _node;

    public ClickedBehaviour(){
        //This is not optimal! Simply to prove concept.
        URL url = this.getClass().getResource("leafIcon.jpg");
        _leafIcon = new ImageIcon(url);
    }
    
    public void setNode(URLTreeNode myNode) {
        _node = myNode;
    }
    
    public Icon getLeafIcon(){
        return _leafIcon;
    }
    
    public void actionPerformed(ActionEvent evt) {
        System.err.print("clicked: ");
        if (_node != null){
            System.err.println(_node.getURL().toExternalForm());
        }else{
            System.err.println("Unknown node");
        }
    }
}
