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
import java.net.URLConnection;
import java.util.Hashtable;
import java.io.PushbackInputStream;
import java.io.BufferedInputStream;
import java.util.Vector;

/** 
 * A netiquette control class: do not visit pages that do not want
 * robots. (istr: Maybe not so very useful for a security checker ;)
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class RobotExclusion {
	String myUserAgent;
	// user agent (name) of this crawler, all lower-case
	Hashtable entries = new Hashtable();
	
	// maps from a website ("host:port") to String[]
	/** 
	 * Make a RobotExclusion object.
	 * @param userAgent name of the robot using this object, as shown
	 * in the User-Agent header fields of its HTTP requests.  Use
	 * null for anonymous robots.
	 */
	public RobotExclusion ( String userAgent ) {
		myUserAgent = userAgent.toLowerCase();
	}

	/** 
	 * Check whether a URL is disallowed by robots.txt.
	 * @param url URL to test
	 * @return true if url's Web site denies robot access to the url
	 */
	public boolean disallowed ( URL url ) {
		if ( !url.getProtocol().startsWith( "http" ) )
			// only HTTP URLs are protected by robots.txt
			return false;
		String website = getWebSite( url );
		String[] rules = (String[]) entries.get( website );
		if ( rules == null ) {
			rules = getRobotsTxt( website, myUserAgent );
			entries.put( website, rules );
		}
		String path = url.getFile();
		for ( int i = 0; i < rules.length; ++i ) {
			if ( path.startsWith( rules[ i ] ) ) {
				//System.err.println ("disallowed by rule " + rules[i]);
				return true;
			}
		//System.err.println ("allowed by rule " + rules[i]);
		}
		return false;
	}

	/** * Clear the cache of robots.txt entries. */
	public void clear () {
		entries.clear();
	}

	/* 
	 * Implementation
	 * 
	 */
	String getWebSite ( URL url ) {
		String hostname = url.getHost();
		int port = url.getPort();
		return port != -1 ? hostname + ":" + port : hostname;
	}
	Vector rulebuf = new Vector();

	String[] getRobotsTxt ( String website, String userAgent ) {
		try {
			URL robotstxtURL = new URL( "http://" + website + "/robots.txt" );
			URLConnection uc = SecurityPolicy.getPolicy().openConnection( robotstxtURL );
			PushbackInputStream in = new PushbackInputStream( new BufferedInputStream( uc.getInputStream() ) );
			rulebuf.setSize( 0 );
			boolean relevant = false,  specific = false;
			String lastFieldName = null;
			while ( readField( in ) ) {
				//System.err.println (fieldName + ":" + fieldValue);
				if ( fieldName == null ) { // end of record
					if ( specific )
						break; // while loop
						relevant = false;
				} else {
					if ( fieldName.equals( "user-agent" ) ) {
						if ( lastFieldName != null && lastFieldName.equals( "disallow" ) ) {
							// end of record
							if ( specific )
								break; // while loop
								relevant = false;
						}
						if ( userAgent != null && userAgent.indexOf( fieldValue.toLowerCase() ) != -1 ) {
							relevant = true;
							specific = true;
							rulebuf.setSize( 0 );
						} else {
							if ( fieldValue.equals( "*" ) ) {
								relevant = true;
								rulebuf.setSize( 0 );
							}
						}
					} else {
						if ( relevant && fieldName.equals( "disallow" ) ) {
							rulebuf.addElement( fieldValue );
						} else { // end of record
							if ( specific )
								break; // while loop
								relevant = false;
						}
					}
				}
				lastFieldName = fieldName;
			}
			in.close();
			String[] rules = new String[rulebuf.size()];
			rulebuf.copyInto( rules );
			return rules;
		} 
		catch ( Exception e ) {
			// debugging only
			// System.err.println ("RobotExclusion: error while retrieving " + website + "/robots.txt:");
			// e.printStackTrace ();
			return new String[0];
		}
	}
	String fieldName,  fieldValue;
	static final int MAX_LINE_LENGTH = 1024;
	StringBuffer linebuf = new StringBuffer();

	// Reads one line from the input stream, parsing it into
	// fieldName and fieldValue.  Field name is lower case;
	// whitespace is stripped at both ends of name and value.
	// e.g., User-agent: Webcrawler
	// is parsed into fieldName="user-agent" and fieldValue="Webcrawler".
	// Field-less lines are parsed as fieldName=null and fieldValue=null.
	// Returns true if a line was read, false on end-of-file.
	boolean readField ( PushbackInputStream in )
		throws Exception
	{
		fieldName = null;
		fieldValue = null;
		linebuf.setLength( 0 );
		int c;
		int n = 0;
		boolean saw_eoln = false;
		while ( true ) {
			c = in.read();
			if ( c == -1 )
				break;
			else 
			if ( c == '\r' || c == '\n' )
				saw_eoln = true;
			else 
			if ( saw_eoln ) {
				in.unread( c );
				break;
			} else {
				linebuf.append( (char) c );
			}
			++n;
			if ( n == MAX_LINE_LENGTH )
				break;
		}
		//System.err.println (linebuf);
		if ( n == 0 )
			return false;
		// extract fields from line and return
		String line = linebuf.toString();
		int colon = line.indexOf( ':' );
		if ( colon == -1 ) {
			fieldName = null;
			fieldValue = null;
		} else {
			fieldName = line.substring( 0, colon ).trim().toLowerCase();
			fieldValue = line.substring( colon + 1 ).trim();
		}
		return true;
	}

	public static void main ( String[] argv )
		throws Exception
	{
		RobotExclusion robot = new RobotExclusion( argv[ 0 ] );
		for ( int i = 1; i < argv.length; ++i ) {
			System.out.println( argv[ i ] + ": " + (!robot.disallowed( new URL( argv[ i ] ) ) ? "OK" : "disallowed")
				 );
		}
		System.in.read();
	}
}

