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
import java.net.HttpURLConnection;
import java.io.File;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.util.Vector;

/** 
 * Security policy for the spider. (istr: Maybe we will need something far more
 * sophisticated here for a security checker)
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class SecurityPolicy {
	private File tempDir;
	private Vector temps = new Vector();
	
	public SecurityPolicy () {
		String tempDirName;
		try {
			tempDirName = System.getProperty( "websphinx.temp.directory" );
		} 
		catch ( SecurityException e ) {
			tempDirName = null;
		}
		if ( tempDirName == null ) {
			String os = System.getProperty( "os.name" );
			tempDirName = (os.startsWith( "Windows" )) ? "c:\\temp\\" : "/tmp/";
		}
		if ( !(tempDirName.endsWith( "/" ) || tempDirName.endsWith( File.separator )) )
			tempDirName += "/";
		tempDir = new File( tempDirName );
	}

	public URLConnection openConnection ( URL url )
		throws IOException
	{
		URLConnection conn = url.openConnection();
		conn.connect();
		return conn;
	}

	public URLConnection openConnection ( Link link )
		throws IOException
	{
		// get the URL
		int method = link.getMethod();
		URL url;
		switch ( method ) {
			case Link.GET:
				url = link.getPageURL();
				break;
			case Link.POST:
				url = link.getServiceURL();
				break;
			default:
				throw new IOException( "Unknown HTTP method " + link.getMethod() );
		}
		// open a connection to the URL
		URLConnection conn = url.openConnection();
		// set up request headers
		DownloadParameters dp = link.getDownloadParameters();
		if ( dp != null ) {
			conn.setAllowUserInteraction( dp.getInteractive() );
			conn.setUseCaches( dp.getUseCaches() );
			String userAgent = dp.getUserAgent();
			if ( userAgent != null )
				conn.setRequestProperty( "User-Agent", userAgent );
			String types = dp.getAcceptedMIMETypes();
			if ( types != null )
				conn.setRequestProperty( "accept", types );
		}
		// submit the query if it's a POST (GET queries are encoded in the URL)
		if ( method == Link.POST ) {
			if ( conn instanceof HttpURLConnection )
				((HttpURLConnection) conn).setRequestMethod( "POST" );
			String query = link.getQuery();
			if ( query.startsWith( "?" ) )
				query = query.substring( 1 );
			conn.setDoOutput( true );
			conn.setRequestProperty( "Content-type", "application/x-www-form-urlencoded" );
			conn.setRequestProperty( "Content-length", String.valueOf( query.length() ) );
			// commence request
			PrintStream out = new PrintStream( conn.getOutputStream() );
			out.print( query );
			out.flush();
		}
		conn.connect();
		return conn;
	}

	public InputStream readFile ( File file )
		throws IOException
	{
		return new FileInputStream( file );
	}

	public OutputStream writeFile ( File file, boolean append )
		throws IOException
	{
		return new FileOutputStream( file.toString(), append );
	}

	public RandomAccessFile readWriteFile ( File file )
		throws IOException
	{
		return new RandomAccessFile( file, "rw" );
	}

	public void makeDir ( File file )
		throws IOException
	{
		file.mkdirs();
	}

	public File getTemporaryDirectory () {
		return tempDir;
	}

	public File makeTemporaryFile ( String basename, String extension ) {
		File dir = getTemporaryDirectory();
		File f;
		synchronized ( temps ) {
			do 
				f = new File( dir, basename + String.valueOf( (int) (Math.random() * 999999) ) + extension
					 );
			while ( temps.contains( f ) || f.exists() );
			temps.addElement( f );
		}
		return f;
	}

	public void deleteAllTempFiles () {
		synchronized ( temps ) {
			for ( int i = 0; i < temps.size(); ++i ) {
				File f = (File) temps.elementAt( i );
				f.delete();
			}
			temps.setSize( 0 );
		}
	}
	/* 
	 * Global security policy
	 * 
	 */
	private static SecurityPolicy thePolicy = findPolicy();

	private static SecurityPolicy findPolicy () {
		try {
			String policyName = System.getProperty( "websphinx.policy" );
			if ( policyName == null ) {
				return new SecurityPolicy();
			} else {
				try {
					Class cls = Class.forName( policyName );
					return (SecurityPolicy) cls.newInstance();
				} 
				catch ( Throwable t ) {
					System.err.println( "websphinx.SecurityPolicy: cannot instantiate " + policyName );
					System.exit( -1 );
					return null; // doesn't get here
					}
			}
		} 
		catch ( Throwable t ) {
			// assume we're running in a sandbox (like a Web browser)
			String browserName;
			try {
				browserName = System.getProperty( "browser" );
			} 
			catch ( Throwable e ) {
				browserName = null;
			}
			if ( browserName == null )
				browserName = "";
			String browserVersion;
			try {
				browserVersion = System.getProperty( "browser.version" );
			} 
			catch ( Throwable e ) {
				browserVersion = null;
			}
			if ( browserVersion == null )
				browserVersion = "";
			/* 
			 * if (browserName.startsWith ("Netscape")
			 * && browserVersion.startsWith ("4."))
			 * return new Netscape4Policy ();
			 * else
			 */
			return new SecurityPolicy(); // FIX: replace with BrowserPolicy that pops up dialog boxes
			}
	}

	public static SecurityPolicy getPolicy () {
		return thePolicy;
	}
}

