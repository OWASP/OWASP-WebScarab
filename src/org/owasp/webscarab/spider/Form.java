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

import java.net.URL;
import java.net.MalformedURLException;
import java.net.URLEncoder;

/** 
 * &lt;FORM&gt; element in an HTML page.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Form 
	extends Link 
{
	
	/** 
	 * Make a LinkElement from a start tag and end tag and a base URL (for relative references).
	 * The tags must be on the same page.
	 * @param startTag Start tag of element
	 * @param endTag End tag of element
	 * @param base Base URL used for relative references
	 */
	public Form ( Tag startTag, Tag endTag, URL base )
		throws MalformedURLException
	{
		super( startTag, endTag, base );
	}

	/** 
	 * Construct the URL for this form, from its start tag and a base URL (for relative references).
	 * @param tag Start tag of form.
	 * @param base Base URL used for relative references
	 * @return URL to which the button points
	 */
	protected URL urlFromHref ( Tag tag, URL base )
		throws MalformedURLException
	{
		String href = tag.getHTMLAttribute( "action" );
		if ( null == href )
			return base;
		return new URL( base, href );
	}

	/** 
	 * Get the method used to access this link.
	 * @return POST if set to POST, GET else (default).
	 */
	public int getMethod () {
		return getHTMLAttribute( "method", "GET" ).equalsIgnoreCase( "post" ) ? POST : GET;
	}

	/** 
	 * Construct the query that would be submitted if the form's SUBMIT button were pressed.
	 * @return a URL representing the submitted form, or null if the form cannot be represented as a URL.
	 */
	public URL makeQuery () {
		return makeQuery( null );
	}

	/** 
	 * Construct the query that would be submitted if the specified button were pressed.
	 * @param button form button that triggers the submission.
	 * @return a URL representing the submitted form, or null if the form cannot be represented as a URL.
	 */
	public URL makeQuery ( FormButton button ) {
		StringBuffer querybuf = new StringBuffer();
		makeQuery( getChild(), querybuf );
		if ( button != null ) {
			String type = button.getHTMLAttribute( "type", "" );
			String name = button.getHTMLAttribute( "name", "" );
			String value = button.getHTMLAttribute( "value", "" );
			if ( type.equalsIgnoreCase( "submit" ) ) {
				passArgument( querybuf, name, value );
			} else {
				if ( type.equalsIgnoreCase( "image" ) ) {
					// simulate an imagemap click
					passArgument( querybuf, name + ".x", "0" );
					passArgument( querybuf, name + ".y", "0" );
				}
			}
		}
		String href = getURL().toExternalForm() + "?";
		if ( querybuf.length() > 0 )
			href += querybuf.toString().substring( 1 ); // deletes '&' from front of querybuf
			try {
			return new URL( href );
		} 
		catch ( MalformedURLException e ) {
			throw new RuntimeException( "internal error: " + e );
		}
	}

	// appends "&name=val&name=val..." to query
	// for all form fields found among elements and their children
	private void makeQuery ( Element elem, StringBuffer query ) {
		for ( Element e = elem; e != null; e = e.getSibling() ) {
			String tagName = e.getTagName();
			if ( tagName == Tag.INPUT ) {
				String type = e.getHTMLAttribute( "type", "text" ).toLowerCase();
				if ( type.equals( "text" ) || type.equals( "password" ) || type.equals( "hidden" )
					|| ((type.equals( "checkbox" ) || type.equals( "radio" )) && e.hasHTMLAttribute( "checked" )
					) ) {
					passArgument( query, e.getHTMLAttribute( "name", "" ), e.getHTMLAttribute( "value", "" ) );
				}
			} else {
				if ( tagName == Tag.SELECT ) {
					String name = e.getHTMLAttribute( "name", "" );
					for ( Element opt = e.getChild(); opt != null; opt = opt.getSibling() ) {
						if ( opt.getTagName() == Tag.OPTION && opt.hasHTMLAttribute( "selected" ) ) {
							passArgument( query, name, opt.getHTMLAttribute( "value", "" ) );
						}
					}
				} else {
					if ( tagName == Tag.TEXTAREA ) {
						passArgument( query, e.getHTMLAttribute( "name", "" ), e.toText() );
					} else {
						makeQuery( e.getChild(), query );
					}
				}
			}
		}
	}

	private void passArgument ( StringBuffer query, String name, String value ) {
		try {
			query.append( '&' );
			query.append( URLEncoder.encode( name, "UTF-8" ) ); // FIXME: should name be encoded?
			query.append( '=' );
			query.append( URLEncoder.encode( value, "UTF-8" ) );
		} 
		catch ( java.io.UnsupportedEncodingException e ) {
			e.printStackTrace();
		}
	}
}

