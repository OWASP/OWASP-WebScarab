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

import java.util.Iterator;
import org.owasp.util.StringUtil;

/** 
 * Tag pattern.  Tag patterns are regular expressions over
 * the alphabet of HTML tags.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class TagExp 
	extends RegExp 
{
	String stringRep;
	
	public TagExp ( String pattern ) {
		super( toRegExp( pattern ) );
		stringRep = pattern;
	}

	public boolean equals ( Object object ) {
		if ( !(object instanceof TagExp) )
			return false;
		TagExp p = (TagExp) object;
		return p.stringRep.equals( stringRep );
	}

	public String toString () {
		return stringRep;
	}

	public PatternMatcher match ( Region region ) {
		return new TagExpMatcher( this, region );
	}
	static HTMLParser parser = new HTMLParser();

	public static String toRegExp ( String tagexp ) {
		StringBuffer output = new StringBuffer();
		// parse the tagexp as HTML
		Page page;
		//System.err.println ("Parsing: " + tagexp);
		synchronized ( parser ) {
			page = new Page( null, tagexp, parser );
		}
		// canonicalize the tags
		Region[] tokens = page.getTokens();
		for ( int i = 0; i < tokens.length; ++i ) {
			//System.err.println ("tok=" + tokens[i].toHTML());
			if ( tokens[ i ] instanceof Tag )
				canonicalizeTagPattern( output, (Tag) tokens[ i ] );
			else
				translateText( output, tokens[ i ].toString() );
		}
		//System.err.println ("regexp=" + output);
		return output.toString();
	}

	static void canonicalizeTag ( StringBuffer output, Tag tag, int j ) {
		String tagName = tag.getTagName();
		if ( tagName == Tag.COMMENT )
			return ; // don't put comments or decls in the canonicalization
			output.append( '<' );
		if ( tag.isEndTag() )
			output.append( '/' );
		output.append( tagName );
		output.append( '#' );
		output.append( String.valueOf( j ) );
		output.append( '#' );
		if ( tag.countHTMLAttributes() > 0 ) {
			String[] attrs = tag.getHTMLAttributes();
			sortAttrs( attrs );
			for ( int i = 0; i < attrs.length;  ) {
				String name = attrs[ i++ ];
				String value = attrs[ i++ ];
				output.append( ' ' );
				output.append( name );
				if ( value != Region.TRUE ) {
					output.append( '=' );
					value = encodeAttrValue( value );
					output.append( value );
				}
				output.append( ' ' );
			}
		}
		output.append( '>' );
	}

	static void canonicalizeTagPattern ( StringBuffer output, Tag tag ) {
		String tagName = tag.getTagName();
		if ( tagName == Tag.COMMENT )
			return ; // don't put comments or decls in the canonicalization
			output.append( '<' );
		if ( tag.isEndTag() )
			output.append( '/' );
		translatePattern( output, tagName, "#" );
		output.append( '#' );
		output.append( "\\d+" );
		output.append( '#' );
		output.append( "[^>]*" );
		if ( tag.countHTMLAttributes() > 0 ) {
			String[] attrs = tag.getHTMLAttributes();
			sortAttrs( attrs );
			for ( int i = 0; i < attrs.length;  ) {
				String name = attrs[ i++ ];
				String value = attrs[ i++ ];
				output.append( ' ' );
				translatePattern( output, name, "= >" );
				if ( value != Region.TRUE ) {
					output.append( '=' );
					value = encodeAttrValue( value );
					translatePattern( output, value, " >" );
				}
				output.append( ' ' );
				output.append( "[^>]*" );
			}
		}
		output.append( '>' );
	}

	static void sortAttrs ( String[] attrs ) {
		// simple insertion sort suffices (since attrs.length is
		// almost always less than 5
		for ( int i = 2; i < attrs.length; i += 2 ) {
			String name = attrs[ i ];
			String value = attrs[ i + 1 ];
			int j;
			for (j = i; j > 0 && attrs[ j - 2 ].compareTo( name ) > 0; j -= 2 ) {
				attrs[ j ] = attrs[ j - 2 ];
				attrs[ j + 1 ] = attrs[ j - 1 ];
			}
			attrs[ j ] = name;
			attrs[ j + 1 ] = value;
		}
	}

	static String encodeAttrValue ( String value ) {
		if ( value.indexOf( '%' ) != -1 )
			value = StringUtil.replace( value, "%", "%25" );
		if ( value.indexOf( ' ' ) != -1 )
			value = StringUtil.replace( value, " ", "%20" );
		if ( value.indexOf( '<' ) != -1 )
			value = StringUtil.replace( value, "<", "%3C" );
		if ( value.indexOf( '>' ) != -1 )
			value = StringUtil.replace( value, ">", "%3E" );
		return value;
	}

	static String translatePattern ( StringBuffer output, String s, String delimiters ) {
		s = Wildcard.toRegExp( s );
		boolean inEscape = false;
		int len = s.length();
		for ( int i = 0; i < len; ++i ) {
			char c = s.charAt( i );
			if ( inEscape ) {
				output.append( c );
				inEscape = false;
			} else {
				if ( c == '\\' ) {
					output.append( c );
					inEscape = true;
				} else {
					if ( c == '.' ) {
						output.append( "[^" );
						output.append( delimiters );
						output.append( ']' );
					} else {
						output.append( c );
					}
				}
			}
		}
		return output.toString();
	}

	static void translateText ( StringBuffer output, String s ) {
		// NIY: (@<tag>) and (<tag>@)
		s = StringUtil.replace( s, ".", "(?:<[^>]*>)" );
		output.append( s );
	}

	public static void main ( String[] args )
		throws Exception
	{
		if ( args.length < 2 ) {
			System.err.println( "usage: TagExp <pattern> <source URL>*" );
			return ;
		}
		MatchBox p = new TagExp( args[ 0 ].replace( '_', ' ' ) );
		for ( int i = 1; i < args.length; ++i ) {
			Page page = new Page( new Link( args[ i ] ) );
			//System.out.println (page.substringCanonicalTags (0, page.getEnd()));
			System.out.println( "-----------" + args[ i ] );
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

