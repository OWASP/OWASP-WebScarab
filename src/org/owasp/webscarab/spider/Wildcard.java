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

import org.owasp.util.StringUtil;

/** 
 * Wildcard pattern.  Wildcards are similar to sh-style file globbing.
 * A wildcard pattern is implicitly anchored, meaning that it must match the entire string.
 * The wildcard operators are:
 * <PRE>
 * ? matches one arbitrary character
 * * matches zero or more arbitrary characters
 * [xyz] matches characters x or y or z
 * {foo,bar,baz}   matches expressions foo or bar or baz
 * ()  grouping to extract fields
 * \ escape one of these special characters
 * </PRE>
 * Escape codes (like \n and \t) and Perl5 character classes (like \w and \s) may also be used.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Wildcard 
	extends RegExp 
{
	String stringRep;
	
	public Wildcard ( String pattern ) {
		super( "^" + toRegExp( pattern ) + "$" );
		stringRep = pattern;
	}

	public boolean equals ( Object object ) {
		if ( !(object instanceof Wildcard) )
			return false;
		Wildcard p = (Wildcard) object;
		return p.stringRep.equals( stringRep );
	}

	public static String toRegExp ( String wildcard ) {
		String s = wildcard;
		int inAlternative = 0;
		int inSet = 0;
		boolean inEscape = false;
		StringBuffer output = new StringBuffer();
		int len = s.length();
		for ( int i = 0; i < len; ++i ) {
			char c = s.charAt( i );
			if ( inEscape ) {
				output.append( c );
				inEscape = false;
			} else {
				switch ( c ) {
					case '\\':
						output.append( c );
						inEscape = true;
						break;
					case '?':
						output.append( '.' );
						break;
					case '*':
						output.append( ".*" );
						break;
					case '[':
						output.append( c );
						++inSet;
						break;
					case ']':
						// FIX: handle [] case properly
						output.append( c );
						--inSet;
						break;
					case '{':
						output.append( "(?:" );
						++inAlternative;
						break;
					case ',':
						if ( inAlternative > 0 )
							output.append( "|" );
						else
							output.append( c );
						break;
					case '}':
						output.append( ")" );
						--inAlternative;
						break;
					case '^':
						if ( inSet > 0 ) {
							output.append( c );
						} else {
							output.append( '\\' );
							output.append( c );
						}
						break;
					case '$':
					case '.':
					case '|':
					case '+':
						output.append( '\\' );
						output.append( c );
						break;
					default:
						output.append( c );
						break;
				}
			}
		}
		if ( inEscape )
			output.append( '\\' );
		return output.toString();
	}

	public static String escape ( String s ) {
		return StringUtil.escape( s, '\\', "\\?*{}()[]" );
	}

	public String toString () {
		return stringRep;
	}

	public static void main ( String[] args )
		throws Exception
	{
		if ( args.length < 2 ) {
			System.err.println( "usage: Wildcard <pattern> <string>*" );
			return ;
		}
		MatchBox p = new Wildcard( args[ 0 ].replace( '_', ' ' ) );
		for ( int i = 1; i < args.length; ++i ) {
			Region r = p.oneMatch( args[ i ] );
			System.out.println( args[ i ] + ": " + (r != null) );
			if ( r != null ) {
				System.out.println( "  [" + r.getStart() + "," + r.getEnd() + "]" + r );
				Region[] groups = r.getFields( "websphinx.groups" );
				if ( groups != null )
					for ( int j = 0; j < groups.length; ++j ) {
						Region s = groups[ j ];
						System.out.println( "    " + "[" + s.getStart() + "," + s.getEnd() + "]" + s );
					}
			}
		}
	}
}

