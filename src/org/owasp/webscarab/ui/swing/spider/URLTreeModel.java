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
import java.net.MalformedURLException;
import java.util.StringTokenizer;
import java.util.Enumeration;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.DefaultMutableTreeNode;

/** 
 * A TreeModel which represents all of the files on a website.
 * 
 * @author <a href="mailto:ray@westhawk.co.uk">Ray Tran</a>
 * @version $Revision: 1.1 $ $Date: 2002/10/30 20:48:22 $
 */
public class URLTreeModel 
	extends DefaultTreeModel 
{
	
	//Don't want this constructor to be used directly
	private URLTreeModel ( TreeNode root ) {
		super( root );
	}
	
	//Don't want this constructor to be used directly
	private URLTreeModel ( TreeNode root, boolean asksAllowsChildren ) {
		super( root, asksAllowsChildren );
	}
	
	/** 
	 * Creates the tree model with just the root node.
	 * 
	 * After calling this constructor it is essential that the
	 * root URL is set by calling <code>setRootURL(url)</code>.
	 * 
	 * @see #setRootURL
	 * @see #URLTreeModel(URL)
	 */
	public URLTreeModel () {
		this( (URL) null );
	}
	
	/** 
	 * Creates the tree model with just the root node.
	 * 
	 * @see #URLTreeModel()
	 */
	public URLTreeModel ( URL rootURL ) {
		super( new URLTreeNode( "Tarantula" ) );
		setRootURL( rootURL );
	}

	/** 
	 * Allows the root node to have a URL assigned to it.
	 * 
	 * @param url the URL to assign to the root node
	 */
	public void setRootURL ( URL url ) {
		((URLTreeNode) root).setURL( url );
	}

	/** 
	 * Convenience method which allows the string representation
	 * of a URL to be added to the tree.
	 * 
	 * @param urlStr the String representation of a URL
	 * @throws MalformedURLException
	 */
	public void insertURL ( String urlStr )
		throws MalformedURLException
	{
		URL url = new URL( urlStr );
		insertURL( url );
	}

	private void fireNewNode ( URLTreeNode parent, URLTreeNode node ) {
		Object[] objArr = new Object[]{ node };
		int[] childIndices = new int[]{ parent.getIndex( node ) };
		fireTreeNodesInserted( parent, parent.getPath(), childIndices, objArr );
	}

	/** 
	 * Add a URL to the tree.
	 * 
	 * @param url the url to be added
	 * @return a tree path to the added leaf node 
	 */
	public TreePath insertURL ( URL url ) {
		if ( null == url )
			return null;
		String path = url.getPath();
		String query = url.getQuery();
		String hostname = url.getHost();
		if ( null == hostname )
			hostname = "HOST.NET";
		URLTreeNode parent = (URLTreeNode) root;
		Enumeration topnodes = root.children();
		URLTreeNode hostnode = null;
		URLTreeNode node = null;
		while ( topnodes.hasMoreElements() && null == hostnode ) {
			URLTreeNode hn = (URLTreeNode) topnodes.nextElement();
			if ( hostname.equals( hn.getURL().getHost() ) ) 
				hostnode = hn;
		}
		if ( null == hostnode ) {
			hostnode = new URLTreeNode( url.getProtocol() + "://" + hostname, url );
			((URLTreeNode) root).add( hostnode );
			fireNewNode( (URLTreeNode) root, hostnode );
		}

		parent = hostnode;
		
		StringTokenizer st = new StringTokenizer( path, "/" );
		while ( st.hasMoreTokens() ) {
			String next = st.nextToken();
			boolean matched = false;
			for ( int i = 0,  count = parent.getChildCount(); i < count && !matched; i++ ) {
				if ( parent.getChildAt( i ).toString().equals( next ) ) {
					matched = true;
					parent = (URLTreeNode) parent.getChildAt( i );
				}
			}
			if ( ! matched ) {
				URL nodeURL = ((URLTreeNode) parent).getURL();
				if ( null != nodeURL ) {
					String nodeURLStr = nodeURL.toString();
					if ( ! nodeURLStr.endsWith( "/" ) )
						nodeURLStr += "/";
					nodeURLStr += next;
					try {
						nodeURL = new URL( nodeURLStr );
					} 
					catch ( MalformedURLException ex ) {
						ex.printStackTrace();
					}
				}
				node = new URLTreeNode( next, nodeURL );
				parent.add( node );
				fireNewNode( parent, node );
				parent = node;
			}
		}
		return null == node ? null : new TreePath( getPathToRoot( hostnode ) );
	}

	/** 
	 * Set the Behaviour object which applies to the node representing
	 * the given URL.
	 * 
	 * @param url the url for the node
	 * @param behave the Behaviour for the node
	 * @returns boolean - true if the node was found, false otherwise.
	 */
	public boolean setBehaviourForURL ( URL url, Behaviour behave ) {
		boolean result = false;
		if ( url != null ) {
			String path = url.getPath();
			String query = url.getQuery();
			URLTreeNode parent = (URLTreeNode) root;
			StringTokenizer st = new StringTokenizer( path, "/" );
			while ( st.hasMoreTokens() ) {
				String next = st.nextToken();
				for ( int i = 0,  count = parent.getChildCount(); i < count; i++ ) {
					if ( parent.getChildAt( i ).toString().equals( next ) ) {
						parent = (URLTreeNode) parent.getChildAt( i );
						break;
					}
				}
			}
			if ( parent.getURL().equals( url ) ) {
				result = true;
				Behaviour oldBehave = parent.getBehaviour();
				if ( oldBehave.equals( behave ) == false ) {
					parent.setBehaviour( behave );
					behave.setNode( parent );
					fireTreeNodesChanged( parent, parent.getPath(), null, null );
				}
			}
		}
		return result;
	}
}

