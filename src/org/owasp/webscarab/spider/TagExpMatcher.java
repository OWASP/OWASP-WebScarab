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
 * A pattern matcher that creates results over valid HTML tags.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
class TagExpMatcher 
	extends PatternMatcher 
{
	protected TagExp _tagexp;
	protected Region _source;
	protected Matcher _matcher;
	protected String _input;
	
	public TagExpMatcher ( TagExp tagexp, Region source ) {
		_tagexp = tagexp;
		_source = source;
		_input = source.getSource().substringCanonicalTags( source.getStart(), source.getLength() );
		_matcher = _tagexp._pattern.matcher( _input );
	}

	protected Region findNext () {
		if ( _matcher.find() ) {
			Page page = _source.getSource();
			String canon = _input;
			Region match = mapCanonical2Region( page, canon, _matcher.start(), _matcher.end() );
			int n = _matcher.groupCount();
			Region[] groups = new Region[n];
			for ( int i = 0; i < n; ++i ) {
				Region r = mapCanonical2Region( page, canon, _matcher.start( i + 1 ), _matcher.end( i + 1
					 ) );
				groups[ i ] = r;
				match.setField( _tagexp._fields[ i ] != null ? _tagexp._fields[ i ] : String.valueOf( i ), 
					r );
			}
			match.setFields( MatchBox.GROUPS, groups );
			return match;
		} else {
			return null;
		}
	}

	final static Region mapCanonical2Region ( Page page, String canon, int start, int end ) {
		// NIY: (@ and @)
		Region[] tokens = page.getTokens();
		int ft,  lt;
		if ( start == end ) {
			ft = prevTag( canon, start );
			lt = nextTag( canon, end );
			if ( ft != -1 )
				if ( lt != -1 )
					return new Region( page, tokens[ ft ].getEnd(), tokens[ lt ].getStart() );
				else
					return new Region( page, tokens[ ft ].getEnd(), page.getEnd() );
			else 
			if ( lt != -1 )
				return new Region( page, page.getStart(), tokens[ lt ].getStart() );
			else
				return page;
		} else {
			ft = nextTag( canon, start );
			lt = prevTag( canon, end );
			Tag f = (Tag) tokens[ ft ];
			Tag l = (Tag) tokens[ lt ];
			Element e = f.getElement();
			if ( e != null && e.getStart() == f.getStart() && e.getEnd() == l.getEnd() )
				return e;
			else 
			if ( ft == lt )
				return tokens[ ft ];
			else
				return tokens[ ft ].span( tokens[ lt ] );
		}
	}

	final static int nextTag ( String canon, int p ) {
		return indexOfTag( canon, canon.indexOf( '<', p ) );
	}

	final static int prevTag ( String canon, int p ) {
		if ( p == 0 )
			return -1;
		return indexOfTag( canon, canon.lastIndexOf( '<', p - 1 ) );
	}

	final static int indexOfTag ( String canon, int p ) {
		if ( p == -1 )
			return -1;
		int s = canon.indexOf( '#', p );
		if ( s == -1 )
			return -1;
		int e = canon.indexOf( '#', s + 1 );
		if ( e == -1 )
			return -1;
		return Integer.parseInt( canon.substring( s + 1, e ) );
	}
}

