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
import java.util.Vector;

/** 
 * Base class that holds results of pattern matchers.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public abstract class MatchBox 
	implements Serializable 
{
	
	public static final String GROUPS = "Pattern.groups";

	public abstract PatternMatcher match ( Region region );

	public boolean found ( Region region ) {
		return match( region ).hasNext();
	}

	public Region oneMatch ( Region region ) {
		return match( region ).nextMatch();
	}

	public Region[] allMatches ( Region region ) {
		Vector v = new Vector();
		PatternMatcher it = match( region );
		Region r;
		while ( (r = it.nextMatch()) != null ) 
			v.addElement( r );
		Region[] regions = new Region[v.size()];
		v.copyInto( regions );
		return regions;
	}

	public boolean found ( String string ) {
		return found( new Page( string ) );
	}

	public Region oneMatch ( String string ) {
		return oneMatch( new Page( string ) );
	}

	public Region[] allMatches ( String string ) {
		return allMatches( new Page( string ) );
	}

	public String[] getFieldNames () {
		return new String[0];
	}

	/** * Return a string representation of the pattern. */
	public abstract String toString ();
}

