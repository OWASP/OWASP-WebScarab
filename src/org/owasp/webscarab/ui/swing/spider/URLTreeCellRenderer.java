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

import java.awt.Component;
import java.awt.Color;
import javax.swing.JTree;
import javax.swing.JLabel;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.UIManager;
import javax.swing.BorderFactory;
import javax.swing.border.Border;

/** 
 * A TreeCellRenderer for URLTreeNodes.
 * 
 * It may be worth overriding
 * <code>validate</code>,
 * <code>revalidate</code>,
 * <code>repaint</code>,
 * and
 * <code>firePropertyChange</code>
 * to improve performance.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:23 $
 */
public class URLTreeCellRenderer 
	extends JLabel 
	implements TreeCellRenderer 
{
	private static final Border BORDER = BorderFactory.createLineBorder( Color.gray, 1 );
	private static final Border NO_BORDER = BorderFactory.createEmptyBorder( 1, 1, 1, 1 );
	
	/** Default Constructor */
	public URLTreeCellRenderer () {
		setOpaque( true );
	}

	/** 
	 * Return the component used to 'rubber stamp' the tree cell onto
	 * the screen.
	 */
	public Component getTreeCellRendererComponent ( JTree tree, Object value, boolean selected, 
		boolean expanded, boolean leaf, int row, boolean hasFocus ) {
		URLTreeNode node = (URLTreeNode) value;
		Behaviour behave = node.getBehaviour();
		if ( selected ) {
			setForeground( UIManager.getColor( "Tree.selectionForeground" ) );
			setBackground( UIManager.getColor( "Tree.selectionBackground" ) );
		} else {
			setForeground( UIManager.getColor( "Tree.textForeground" ) );
			setBackground( UIManager.getColor( "Tree.textBackground" ) );
		}
		if ( leaf ) {
			setIcon( behave.getLeafIcon() );
		} else {
			if ( expanded ) {
				setIcon( behave.getOpenIcon() );
			} else {
				setIcon( behave.getClosedIcon() );
			}
		}
		setText( value.toString() );
		if ( hasFocus ) {
			setBorder( BORDER );
		} else {
			setBorder( NO_BORDER );
		}
		return this;
	}
}

