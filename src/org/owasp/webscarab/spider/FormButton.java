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

/** 
 * Button element in an HTML form -- for example, &lt;INPUT TYPE=submit&gt; or &lt;INPUT TYPE=image&gt;.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 * @see Page
 * @see Link
 */
public class FormButton 
	extends Link 
{
	
	/** the form that contains this FormButton */
	public final Form _form;
	
	/** 
	 * Make a LinkElement from a start tag and end tag and its containing form.
	 * The tags and form must be on the same page.
	 * @param startTag Start tag of button
	 * @param endTag End tag of button (or null if none)
	 * @param form Form containing this button
	 */
	public FormButton ( Tag startTag, Tag endTag, Form form )
		throws MalformedURLException
	{
		super( startTag, endTag, null );
		_form = form;
		if ( null == _form )
			throw new MalformedURLException();
	}

	/** 
	 * Get the URL.
	 * @return the URL of the link
	 */
	public URL getURL () {
		if ( null == _url )
			try {
				_url = urlFromHref( getStartTag(), null );
			} 
			catch ( MalformedURLException e ) {
				_url = null;
			}
		return _url;
	}

	/** 
	 * Gets the method used to access this link.
	 * @return GET or POST.
	 */
	public int getMethod () {
		return _form.getMethod();
	}

	/** 
	 * Construct the URL for this button, from its start tag and a base URL (for relative references).
	 * @param tag Start tag of button, such as &lt;INPUT TYPE=submit&gt;.
	 * @param base Base URL used for relative references
	 * @return URL to which the button points
	 */
	protected URL urlFromHref ( Tag tag, URL base )
		throws MalformedURLException
	{
		if ( null == _parent || null == _form )
			return null;
		return _form.makeQuery( this );
	}
}

