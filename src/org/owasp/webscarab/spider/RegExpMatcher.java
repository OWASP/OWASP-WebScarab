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

import java.util.regex.Matcher;

/**
 * Simple regular expression matcher that creates results
 * based on a regular expression pattern.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
class RegExpMatcher 
	extends PatternMatcher 
{
	Matcher _matcher;
	RegExp _regexp;
	Region _source;
	
	public RegExpMatcher ( RegExp regexp, Region source ) {
		_regexp = regexp;
		_source = source;
		_matcher = _regexp._pattern.matcher( _source.toString() );
	}

	protected Region findNext () {
		if ( _matcher.find() ) {
			Page page = _source.getSource();
			Region match = new Region( page, _matcher.start(), _matcher.end() );
			int n = _matcher.groupCount();
			Region[] groups = new Region[n];
			for ( int i = 0; i < n; ++i ) {
				Region r = new Region( page, _matcher.start( i + 1 ), _matcher.end( i + 1 ) );
								groups[ i ] = r;
				match.setField( _regexp._fields[ i ], r );
			}
			match.setFields( MatchBox.GROUPS, groups );
			return match;
		} else {
			return null;
		}
	}
}

