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
 * 
 * NOTE: This file is an adaption of the WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University
 * This package was released under the Library GPL but maintenance and
 * further development has been discontinued.
 * For a detailed information see http://www.cs.cmu.edu/~rcm/websphinx/
 * and read the README that can be found in this subpackage.
 */
package org.owasp.webscarab.spider;


/** 
 * Default classifier, installed in every crawler by default.
 * <p>On the entire page, this classifier sets the following labels:
 * <ul>
 * <li><b>root</b>: page is the root page of a Web site.  For instance,
 * "http://www.digital.com/" and "http://www.digital.com/index.html" are both
 * marked as root, but "http://www.digital.com/about" is not.
 * </ul>
 * <p>Also sets one or more of the following labels on every link:
 * <ul>
 * <li><b>hyperlink</b>: link is a hyperlink (A, AREA, or FRAME tags) to another page on the Web (using http, file, ftp, or gopher protocols)
 * <li><b>image</b>: link is an inline image (IMG).
 * <li><b>form</b>: link is a form (FORM tag).  A form generally requires some parameters to use.
 * <li><b>code</b>: link points to code (APPLET, EMBED, or SCRIPT).
 * <li><b>remote</b>: link points to a different Web server.
 * <li><b>local</b>: link points to the same Web server.
 * <li><b>same-page</b>: link points to the same page (e.g., by an anchor reference like "#top")
 * <li><b>sibling</b>: a local link that points to a page in the same directory (e.g. "sibling.html")
 * <li><b>descendent</b>: a local link that points downwards in the directory structure (e.g., "deep/deeper/deepest.html")
 * <li><b>ancestor</b>: a link that points upwards in the directory structure (e.g., "../..")
 * </ul>
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class DefaultClassifier 
	implements Classifier 
{
	
	/** * Make a DefaultClassifier. */
	public DefaultClassifier () {}

	/** 
	 * Classify a page.
	 * @param page Page to classify
	 */
	// FIX: use regular expressions throughout this method
	public void classify ( Page page ) {
		Link origin = page.getOrigin();
		String pagePath = origin.getFile();
		String pageFilename = origin.getFilename();
		String pageDir = origin.getDirectory();
		if ( pageFilename.equals( "" ) || pageFilename.startsWith( "index.htm" ) )
			page.setLabel( "root" );
		// FIX: Link needs to resolve "foo/bar/.." and "foo/." to "foo" in order for this
		// stuff to work properly
		Link[] links = page.getLinks();
		if ( links != null ) {
			for ( int i = 0; i < links.length; ++i ) {
				Link link = links[ i ];
				if ( link.getHost().equals( origin.getHost() ) && link.getPort() == origin.getPort() ) {
					link.setLabel( "local" );
					String linkPath = link.getFile();
					String linkDir = link.getDirectory();
					if ( linkPath.equals( pagePath ) )
						link.setLabel( "same-page" );
					else 
					if ( linkDir.equals( pageDir ) )
						link.setLabel( "sibling" );
					else 
					if ( linkDir.startsWith( pageDir ) )
						link.setLabel( "descendent" );
					else 
					if ( pageDir.startsWith( linkDir ) )
						link.setLabel( "ancestor" );
				// NIY: child, parent
				} else {
					link.setLabel( "remote" );
				}
				// Link tag kinds: resource, form, hyperlink
				String tagName = link.getTagName();
				if ( tagName == Tag.IMG )
					link.setLabel( "image" );
				else 
				if ( tagName == Tag.APPLET || tagName == Tag.EMBED || tagName == Tag.SCRIPT )
					link.setLabel( "code" );
				else 
				if ( tagName == Tag.FORM )
					link.setLabel( "form" );
				else 
				if ( tagName == Tag.A || tagName == Tag.AREA || tagName == Tag.FRAME ) {
					String protocol = link.getProtocol();
					if ( (protocol.equals( "http" ) || protocol.equals( "ftp" ) || protocol.equals( "file" )
						|| protocol.equals( "gopher" )) && link.getMethod() == Link.GET )
						link.setLabel( "hyperlink" );
				}
			}
		}
	}
	/** * Priority of this classifier. */
	public static final long priority = 0L;

	/** 
	 * Get priority of this classifier.
	 * @return priority.
	 */
	public long getPriority () {
		return priority;
	}
}

