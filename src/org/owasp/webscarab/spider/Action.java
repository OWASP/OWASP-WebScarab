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

import java.io.Serializable;

/** 
 * Action to be performed encountering some page.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public interface Action 
	extends Serializable
{
	
	/**
	 * Connects an Action to a Crawler.
	 * This method should be called by a Crawler after the action
	 * is added to a Crawler {@link Crawler.setAction( Action )}.
	 * @param Crawler the Crawler this Action is connected to
	 */
	void connected ( Crawler crawler );
	
	/**
	 * Disconnects an Action from a Crawler.
	 * This method should be called by a Crawler after the action
	 * is removed from a Crawler {@link Crawler.setAction( Action )}.
	 * @param Crawler the Crawler this Action is disconnected from
	 */
	void disconnected ( Crawler crawler );
	
	/**
	 * Triggers the action to be taken encountering a Page.
	 * This method should be called from a Crawler directly after a Page
	 * has reached the status "visited".
	 * @param page a Page object the Crawler thoroughly visited
	 */
	void visit ( Page page );
} // interface Action

