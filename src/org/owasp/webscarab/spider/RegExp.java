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

import java.util.Vector;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.io.IOException;
import java.io.ObjectInputStream;
import org.owasp.util.StringUtil;

/** 
 * A match box that creates match results based on a RegExpMatcher.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class RegExp 
	extends MatchBox 
{
	protected String _stringRep;
	protected String[] _fields;
	protected Pattern _pattern;
	
	/**
	 * Creates a RegExp from a regular expression pattern String.
	 * @param stringRep the regular expression pattern
	 */
	public RegExp ( String stringRep ) {
		_stringRep = stringRep;
		init();
	}

	public boolean equals ( Object object ) {
		if ( !(object instanceof RegExp) )
			return false;
		RegExp p = (RegExp) object;
		return p._stringRep.equals( _stringRep );
	}

	private void readObject ( ObjectInputStream in )
		throws IOException, ClassNotFoundException
	{
		in.defaultReadObject();
		init();
	}

	private void init () {
		try {
			_pattern = Pattern.compile( translateFields( _stringRep ) );
		} 
		catch ( PatternSyntaxException pse ) {
			throw new IllegalArgumentException( "syntax error in pattern: " + _stringRep );
		}
	}

	public String[] getFieldNames () {
		return _fields;
	}

	public String toString () {
		return _stringRep;
	}

	public PatternMatcher match ( Region region ) {
		return new RegExpMatcher( this, region );
	}

	public static String escape ( String s ) {
		return StringUtil.escape( s, '\\', "\\^.$|()[]*+?{}" );
	}

	String translateFields ( String s ) {
		Vector vfields = new Vector();
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
					case '(':
						output.append( c );
						if ( s.startsWith( "?{", i + 1 ) ) {
							int start = i + 3;
							int end = s.indexOf( '}', start );
							vfields.addElement( s.substring( start, end ) );
							i = end;
						} else {
							if ( !s.startsWith( "?", i + 1 ) )
								vfields.addElement( String.valueOf( vfields.size() ) );
						}
						break;
					default:
						output.append( c );
						break;
				}
			}
		}
		_fields = new String[vfields.size()];
		vfields.copyInto( _fields );
		return output.toString();
	}

	public static void main ( String[] args )
		throws Exception
	{
		if ( args.length < 2 ) {
			System.err.println( "usage: RegExp <pattern> <source URL>*" );
			return ;
		}
		MatchBox p = new RegExp( args[ 0 ].replace( '_', ' ' ) );
		for ( int i = 1; i < args.length; ++i ) {
			Page page = new Page( new Link( args[ i ] ) );
			System.out.println( "--------------------" + args[ i ] );
			PatternMatcher m = p.match( page );
			for ( Region r = m.nextMatch(); r != null; r = m.nextMatch() ) {
				System.out.println( "[" + r.getStart() + "," + r.getEnd() + "]" + r );
				Iterator it = r.iterateObjectLabels();
				while ( it.hasNext() ) {
					String lbl = (String) it.next();
					Object object = r.getObjectLabel( lbl );
					if ( object instanceof Region ) {
						Region s = (Region) object;
						System.out.println( "    " + lbl + "=[" + s.getStart() + "," + s.getEnd() + "]" + s );
					}
				}
			}
		}
	}
}

