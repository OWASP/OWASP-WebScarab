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

import java.net.URL;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.DefaultMutableTreeNode;

/** 
 * A mutable tree node which represents a URL.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:24 $
 */
public class URLTreeNode 
	extends DefaultMutableTreeNode
	implements Comparable
{
	private URL _url;
	private Behaviour _behaviour;
	
	/** 
	 * Constructor for a node with a name but no URL.
	 * 
	 * Generally only useful for the root node. If this
	 * constructor is used the setURL(URL) method should
	 * be called as soon as convenient.
	 * 
	 * @see #setURL(URL)
	 * @param name - the name of the node
	 */
	public URLTreeNode ( String name ) {
		this( name, null );
	}
	
	/** 
	 * Constructor for a node with a name and a URL.
	 * 
	 * @see #setURL(URL)
	 * @param name - the name of the node
	 * @param url - the URL associated with the node
	 */
	public URLTreeNode ( String name, URL url ) {
		super( name );
		_url = url;
		_behaviour = DefaultBehaviour.getInstance();
	}

	/** 
	 * Return the URL associated with this node.
	 * 
	 * @returns URL - the URL associated with this node, which may be null
	 */
	public URL getURL () {
		return _url;
	}

	/** 
	 * Change the behaviour of this node.
	 * 
	 * @see #getBehaviour()
	 * @see Behaviour
	 * @param behave - the Behaviour for this node.
	 */
	public void setBehaviour ( Behaviour behave ) {
		_behaviour = behave;
	}

	/** 
	 * Get the Behaviour associated with this node.
	 * 
	 * @see #setBehaviour()
	 * @see Behaviour
	 * @returns Behaviour - the Behaviour for this node.
	 */
	public Behaviour getBehaviour () {
		return _behaviour;
	}

	/** 
	 * Add a node as a child of this node.
	 * 
	 * Overrides add from the superclass so that siblings are
	 * always sorted.
	 * 
	 * @param newChild - a MutableTreeNode which is to be a child of this node
	 */
	public void add ( MutableTreeNode newChild ) {
		if ( ! (newChild instanceof URLTreeNode ) )
			throw new IllegalArgumentException( "can only add URLTreeNode" );
		URLTreeNode c = (URLTreeNode) newChild;
		boolean inserted = false;
		for ( int i = 0,  count = getChildCount(); i < count && ! inserted; i++ ) {
			if ( 0 < ((URLTreeNode) getChildAt( i )).compareTo( c ) ) {
				insert( c, i );
				inserted = true;
			}
		}
		if ( ! inserted )
			insert( c, getChildCount() );
	}

	/** 
	 * Allows the URL associated with this node to be changed.
	 * 
	 * Note: the URL can only be changed from null, after that the
	 * URL becomes final.
	 * 
	 * @param url - the URL to associate with this node
	 */
	void setURL ( URL url ) {
		if ( null == _url )
			_url = url;
	}


	public int compareTo ( Object o ) {
		String p = null == _url ? "" : _url.getPath();
		URL u = null != o && ( o instanceof URLTreeNode ) ? ((URLTreeNode) o).getURL() : null;
		String p1 = null != u ? u.getPath() : null == o ? "" : o.toString();
		return p.compareToIgnoreCase( p1 );
	}

/*	public String toString () {
		return ( null == _url ) ? "" : _url.getPath();
	}*/
}

