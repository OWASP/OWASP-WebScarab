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

import java.io.File;
import java.net.URL;
import java.net.MalformedURLException;
import org.owasp.webscarab.util.Prioritized;

/** 
 * Link to a Web page.
 * 
 * @author Rob Miller
 * @see Page
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Link 
	extends Element 
	implements Prioritized 
{
	/** URL of the link */
	protected URL _url;
	/** directory of the link */
	private String _directory;
	/** filename of the link */
	private String _filename;
	/** query string, this needs to be adapted */
	private String _query;
	private String _ref;
	private Page _page;
	private int _depth;
	private String _text = ""; // stored text of link anchor
	private int _status = LinkEvent.NONE;
	private long _priority;
	private DownloadParameters _dp;
	
	// timeouts, etc. to use when downloading this link
	/** 
	 * Make a Link from a start tag and end tag and a base URL (for relative references).
	 * The tags must be on the same page.
	 * @param startTag Start tag of element
	 * @param endTag End tag of element
	 * @param base Base URL used for relative references
	 */
	public Link ( Tag startTag, Tag endTag, URL base )
		throws MalformedURLException
	{
		super( startTag, endTag );
		_url = urlFromHref( startTag, base );
		_depth = startTag.getSource().getDepth() + 1;
	}
	
	/** * Make a Link from a URL. */
	public Link ( URL url ) {
		super( new Tag( new Page( "" ), 0, 0, "", true ), null );
		_url = url;
		_depth = 0;
	}
	
	/** * Make a Link from a File. */
	public Link ( File file )
		throws MalformedURLException
	{
		this( FileToURL( file ) );
	}
	
	/** 
	 * Make a Link from a string URL.
	 * @exception java.net.MalformedURLException if the URL is invalid
	 */
	public Link ( String href )
		throws MalformedURLException
	{
		this( new URL( href ) );
		_depth = 0;
	}

	/** Eliminate all references to page content. */
	public void discardContent () {
		_parent = null;
		_child = null;
		_sibling = null;
	}

	/** Disconnect this link from its downloaded page (throwing away the page). */
	public void disconnect () {
		_page = null;
		_status = LinkEvent.NONE;
	}

	/** 
	 * Get depth of link in crawl.
	 * @return depth of link from root (depth of roots is 0)
	 */
	public int getDepth () {
		return _depth;
	}

	/** 
	 * Get the URL.
	 * @return the URL of the link
	 */
	public URL getURL () {
		return _url;
	}

	/** 
	 * Get the network protocol of the link, like "ftp" or "http".
	 * @return the protocol portion of the link's URL
	 */
	public String getProtocol () {
		return getURL().getProtocol();
	}

	/** 
	 * Get the hostname of the link, like "www.cs.cmu.edu".
	 * @return the hostname portion of the link's URL
	 */
	public String getHost () {
		return getURL().getHost();
	}

	/** 
	 * Get the port number of the link.
	 * @return the port number of the link's URL, or -1 if no port number
	 * is explicitly specified in the URL
	 */
	public int getPort () {
		return getURL().getPort();
	}

	/** 
	 * Get the information part of the link, like
	 * "/home/dir/index.html?query".  Equivalent to getURL().getFile().
	 * @return the filename portion of the link's URL
	 */
	public String getFile () {
		return getURL().getFile();
	}

	/** 
	 * Get the directory part of the link, like "/home/dir/".
	 * Always starts and ends with '/'.
	 * @return the directory portion of the link's URL
	 */
	public String getDirectory () {
		if ( null == _directory )
			parseURL();
		return _directory;
	}

	/** 
	 * Get the filename part of the link, like "index.html".
	 * Never contains '/'; may be the empty string.
	 * @return the filename portion of the link's URL
	 */
	public String getFilename () {
		if ( null == _filename )
			parseURL();
		return _filename;
	}

	/** 
	 * Get the query part of the link, like "?query".
	 * Either starts with a '?', or is empty.
	 * @return the query portion of the link's URL
	 */
	public String getQuery () {
		if ( null == _query )
			parseURL();
		return _query;
	}

	/** 
	 * Get the anchor reference of the link, like "#ref".
	 * Either starts with '#', or is empty.
	 * @return the anchor reference portion of the link's URL
	 */
	public String getRef () {
		if ( null == _ref )
			parseURL();
		return _ref;
	}

	/** 
	 * Get the URL of a page, omitting any anchor reference (like #ref).
	 * @return the URL sans anchor reference
	 */
	public URL getPageURL () {
		return getPageURL( getURL() );
	}

	/** 
	 * Get the URL of a page, omitting any anchor reference (like #ref).
	 * @return the URL sans anchor reference
	 */
	public static URL getPageURL ( URL url ) {
		String href = url.toExternalForm();
		int i = href.indexOf( '#' );
		try {
			return (i != -1) ? new URL( href.substring( 0, i ) ) : url;
		} 
		catch ( MalformedURLException e ) {
			return url;
		}
	}

	/** 
	 * Get the URL of a Web service, omitting any query or anchor reference.
	 * @return the URL sans query and anchor reference
	 */
	public URL getServiceURL () {
		return getServiceURL( getURL() );
	}

	/** 
	 * Get the URL of a Web service, omitting any query or anchor reference.
	 * @return the URL sans query and anchor reference
	 */
	public static URL getServiceURL ( URL url ) {
		String href = url.toExternalForm();
		int i = href.indexOf( '?' );
		try {
			return (i != -1 && url.getProtocol().equals( "http" )) ? new URL( href.substring( 0, i ) ) : getPageURL( url );
		} 
		catch ( MalformedURLException e ) {
			return url;
		}
	}

	/** 
	 * Get the URL of a page's directory.
	 * @return the URL sans filename, query and anchor reference
	 */
	public URL getDirectoryURL () {
		return getDirectoryURL( getURL() );
	}

	/** 
	 * Get the URL of a page's directory.
	 * @return the URL sans filename, query and anchor reference
	 */
	public static URL getDirectoryURL ( URL url ) {
		String file = url.getFile();
		int qmark = file.indexOf( '?' );
		if ( qmark == -1 || !url.getProtocol().equals( "http" ) )
			qmark = file.length();
		// find pivotal separator (between directory and filename)
		int pivot = file.lastIndexOf( '/', Math.max( qmark - 1, 0 ) );
		try {
			if ( pivot == -1 )
				return new URL( url, "/" );
			else 
			if ( pivot == file.length() - 1 )
				return url;
			else
				return new URL( url, file.substring( 0, pivot + 1 ) );
		} 
		catch ( MalformedURLException e ) {
			return url;
		}
	}

	/** 
	 * Get the URL of a page's parent directory.
	 * @return the URL sans filename, query and anchor reference
	 */
	public URL getParentURL () {
		return getParentURL( getURL() );
	}

	/** 
	 * Get the URL of a page's parent directory.
	 * @return the URL sans filename, query and anchor reference
	 */
	public static URL getParentURL ( URL url ) {
		URL dirURL = getDirectoryURL( url );
		if ( !dirURL.equals( url ) )
			return dirURL;
		String dir = dirURL.getFile();
		int lastSlash = dir.length() - 1;
		if ( lastSlash == 0 )
			return dirURL;
		int penultSlash = dir.lastIndexOf( '/', lastSlash - 1 );
		if ( penultSlash == -1 )
			return dirURL;
		try {
			return new URL( url, dir.substring( 0, penultSlash + 1 ) );
		} 
		catch ( MalformedURLException e ) {
			return dirURL;
		}
	}

	// computes relative HREF for URL <there> when the current location
	// is URL <here>
	public static String relativeTo ( URL here, URL there ) {
		if ( here == null )
			return there.toString();
		//System.err.println ("From: " + here);
		//System.err.println ("To:   " + there);
		if ( here.getProtocol().equals( there.getProtocol() ) && here.getHost().equals( there.getHost() )
			&& here.getPort() == there.getPort() ) {
			String fn = relativeTo( here.getFile(), there.getFile() );
			String ref = there.getRef();
			return (ref != null) ? fn + ref : fn;
		} else {
			//System.err.println ("Use: " + there);
			return there.toString();
		}
	}

	// computes relative HREF for URL <there> when the current location
	// is URL <here>
	public static String relativeTo ( URL here, String there ) {
		if ( here == null )
			return there;
		try {
			return relativeTo( here, new URL( here, there ) );
		} 
		catch ( MalformedURLException e ) {
			return there;
		}
	}

	// computes relative HREF for filename <there> when the current location
	// is filename <here>
	private static String relativeTo ( String here, String there ) {
		StringBuffer result = new StringBuffer();
		int lcp = 0;
		while ( true ) {
			int i = here.indexOf( '/', lcp );
			int j = there.indexOf( '/', lcp );
			if ( i == -1 || i != j || !here.regionMatches( lcp, there, lcp, i - lcp ) )
				break;
			lcp = i + 1;
		}
		// assert: first lcp characters of here and there are identical
		//         and (lcp==0 or here[lcp-1] == '/')
		// here[0..lcp-1] is the common ancestor directory of here and there
		// count hops up from here to the common ancestor
		for ( int i = here.indexOf( '/', lcp ); i != -1; i = here.indexOf( '/', i + 1 ) ) {
			result.append( ".." );
			result.append( '/' );
		}
		// append path down from common ancestor to there
		result.append( there.substring( lcp ) );
		//System.out.println ("Use:   " + result);
		//System.out.println ();
		return result.toString();
	}

	/** 
	 * Convert a local filename to a URL.
	 * For example, if the filename is "C:\FOO\BAR\BAZ",
	 * the resulting URL is "file:/C:/FOO/BAR/BAZ".
	 * @param file File to convert
	 * @return URL corresponding to file
	 */
	public static URL FileToURL ( File file )
		throws MalformedURLException
	{
		return new URL( "file:" + toURLDelimiters( file.getAbsolutePath() ) );
	}

	/** 
	 * Convert a file: URL to a filename appropriate to the
	 * current system platform.  For example, on MS Windows,
	 * if the URL is "file:/FOO/BAR/BAZ", the resulting
	 * filename is "\FOO\BAR\BAZ".
	 * @param url URL to convert
	 * @return File corresponding to url
	 * @exception MalformedURLException if url is not a
	 * file: URL.
	 */
	public static File URLToFile ( URL url )
		throws MalformedURLException
	{
		if ( !url.getProtocol().equals( "file" ) )
			throw new MalformedURLException();
		String path = url.getFile();
		path = path.replace( '/', File.separatorChar );
		// for MSWindows: change pathnames of the
		// form /X:/ to X:/
		if ( path.length() > 3 && path.charAt( 0 ) == File.separatorChar && path.charAt( 2 ) == ':'
			&& path.charAt( 3 ) == File.separatorChar )
			path = path.substring( 1 );
		return new File( path );
	}

	public static String toURLDelimiters ( String path ) {
		path = path.replace( '\\', '/' );
		if ( !path.startsWith( "/" ) )
			path = "/" + path;
		return path;
	}

	/** 
	 * Get the downloaded page to which the link points.
	 * @return the Page object, or null if the page hasn't been downloaded.
	 */
	public Page getPage () {
		return _page;
	}

	/** 
	 * Set the page corresponding to this link.
	 * @param page Page to which this link points
	 */
	public void setPage ( Page page ) {
		_page = page;
	}
	/** * Use the HTTP GET method to download this link. */
	public static final int GET = 0;
	/** * Use the HTTP POST method to access this link. */
	public static final int POST = 1;

	/** 
	 * Get the method used to access this link.
	 * @return GET or POST.
	 */
	public int getMethod () {
		return GET;
	}

	/** 
	 * Convert the link's URL to a String
	 * @return the URL represented as a string
	 */
	public String toURL () {
		return getURL().toExternalForm();
	}

	/** 
	 * Generate a human-readable description of the link.
	 * @return a description of the link, in the form "[url]".
	 */
	public String toDescription () {
		return (_text.length() > 0 ? _text + " " : "") + "[" + getURL() + "]";
	}

	/** 
	 * Convert the region to tagless text.
	 * @return a string consisting of the text in the page contained by this region
	 */
	public String toText () {
		return _text;
	}

	/** 
	 * Set the tagless-text representation of this region.
	 * @param text a string consisting of the text in the page contained by this region
	 */
	public void setText ( String text ) {
		_text = text;
	}

	private void parseURL () {
		String protocol = getProtocol();
		String file = getFile();
		int qmark = file.indexOf( '?' );
		if ( qmark == -1 || !protocol.equals( "http" ) ) {
			_query = "";
			qmark = file.length();
		} else {
			_query = file.substring( qmark + 1 );
			file = file.substring( 0, qmark );
		}
		int slash = file.lastIndexOf( '/', Math.max( qmark - 1, 0 ) );
		if ( slash == -1 ) {
			_directory = "";
			_filename = file;
		} else {
			_directory = file.substring( 0, slash + 1 );
			_filename = file.substring( slash + 1 );
		}
		_ref = getURL().getRef();
		if ( null == _ref )
			_ref = "";
	}

	/** 
	 * Construct the URL for a link element, from its start tag and a base URL (for relative references).
	 * @param tag Start tag of link, such as &lt;A HREF="/foo/index.html"&gt;.
	 * @param base Base URL used for relative references
	 * @return URL to which the link points
	 */
	protected URL urlFromHref ( Tag tag, URL base )
		throws MalformedURLException
	{
		// element is a link -- make an instance of Link.
		String hrefAttr = getHrefAttributeName( tag );
		String href = tag.getHTMLAttribute( hrefAttr );
		if ( tag._tagName == Tag.APPLET ) {
			String codebase = tag.getHTMLAttribute( "codebase" );
			if ( codebase != null )
				base = new URL( base, codebase );
		}
		return new URL( base, href );
	}

	/** 
	 * Copy the link's start tag, replacing the URL.  Note that the name of the attribute containing the URL
	 * varies from tag to tag: sometimes it is called HREF, sometimes SRC, sometimes CODE, etc.
	 * This method changes the appropriate attribute for this tag.
	 * @param newHref New URL or relative reference; e.g. "http://www.cs.cmu.edu/" or "/foo/index.html".
	 * @return copy of this link's start tag with its URL attribute replaced.  The copy is
	 * a region of a fresh page containing only the tag.
	 */
	public Tag replaceHref ( String newHref ) {
		Tag tag = _startTag;
		if ( tag.getTagName() == Tag.APPLET ) {
			int i = newHref.lastIndexOf( '/' );
			if ( i != -1 ) {
				tag = _startTag.replaceHTMLAttribute( "codebase", newHref.substring( 0, i + 1 ) );
				newHref = newHref.substring( i + 1 );
			}
		}
		String hrefAttrName = getHrefAttributeName( tag );
		if ( hrefAttrName == null )
			return tag;
		return tag.replaceHTMLAttribute( hrefAttrName, newHref );
	}

	private static String getHrefAttributeName ( Tag tag ) {
		return (String) HTMLParser.linktag.get( tag.getTagName() );
	}

	/** 
	 * Get the status of the link.  Possible values are defined in LinkEvent.
	 * @return last event that happened to this link
	 */
	public int getStatus () {
		return _status;
	}

	/** 
	 * Set the status of the link.  Possible values are defined in LinkEvent.
	 * @param event the event that just happened to this link
	 */
	public void setStatus ( int event ) {
		_status = event;
	}

	/** * Get the priority of the link in the crawl. */
	public long getPriority () {
		return _priority;
	}

	/** * Set the priority of the link in the crawl. */
	public void setPriority ( long priority ) {
		_priority = priority;
	}

	/** * Get the download parameters used for this link.  Default is null. */
	public DownloadParameters getDownloadParameters () {
		return _dp;
	}

	/** * Set the download parameters used for this link. */
	public void setDownloadParameters ( DownloadParameters dp ) {
		_dp = dp;
	}
/* 
 * Testing
 * 
 * 
 * public static void main (String[] args) throws Exception {
 * if (args[0].equals ("file"))
 * System.out.println (Link.FileToURL (new File (args[1])));
 * else if (args[0].equals ("url"))
 * System.out.println (Link.URLToFile (new URL (args[1])));
 * }
 * 
 * 
 */
}

