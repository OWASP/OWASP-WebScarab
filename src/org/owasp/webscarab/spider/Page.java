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
import java.io.IOException;
import java.io.InputStream;
import org.owasp.util.StringUtil;

/** 
 * A Web page.  Although a Page can represent any MIME type, it mainly
 * supports HTML pages, which are automatically parsed.  The parsing produces
 * a list of tags, a list of words, an HTML parse tree, and a list of links.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Page 
	extends Region 
{
	// Permanent content
	Link origin;
	long lastModified = 0;
	long expiration = 0;
	String contentType;
	String contentEncoding;
	int responseCode = -1;
	String responseMessage = null;
	URL base;
	String title;
	Link[] links;
	/** If page was downloaded from Net, represents number of
	    callers who want to keep the content.
	 If page was created from a string, set to -1.
	 Discardable content (thrown away when contentLock falls to 0) */
	int contentLock;
	String _content;
	Region[] tokens;
	Text[] words;
	Tag[] tags;
	Element[] elements;
	Element root;
	String canonicalTags;
	
	/** 
	 * Make a Page by downloading and parsing a Link.
	 * @param link Link to download
	 */
	public Page ( Link link )
		throws IOException
	{
		this( link, new HTMLParser() );
	}
	
	/** 
	 * Make a Page by downloading a Link.
	 * @param link Link to download
	 * @param parser HTML parser to use
	 */
	public Page ( Link link, HTMLParser parser )
		throws IOException
	{
		super( null, 0, 0 );
		_source = this;
		origin = link;
		base = getURL();
		download( parser );
		link.setPage( this );
	}
	
	/** 
	 * Make a Page from a URL and a string of HTML.
	 * The created page has no originating link, so calls to getURL(), getProtocol(), etc. will fail.
	 * @param url URL to use as a base for relative links on the page
	 * @param content the HTML content of the page
	 */
	public Page ( URL url, String content ) {
		this( url, content, new HTMLParser() );
	}
	
	/** 
	 * Make a Page from a URL and a string of HTML.
	 * The created page has no originating link, so calls to getURL(), getProtocol(), etc. will fail.
	 * @param url URL to use as a base for relative links on the page
	 * @param content the HTML content of the page
	 * @param parser HTML parser to use
	 */
	public Page ( URL url, String content, HTMLParser parser ) {
		this( content );
		base = url;
		parse( parser );
	}
	
	/** 
	 * Make a Page from a string of content.  The content is not parsed.
	 * The created page has no originating link, so calls to getURL(), getProtocol(), etc. will fail.
	 * @param content HTML content of the page
	 */
	public Page ( String content ) {
		super( null, 0, content.length() );
		_source = this;
		_content = content;
		contentLock = -1;
	}

	/** 
	 * Downloads the page.  The downloaded page is parsed
	 * if its MIME type is HTML or unspecified.
	 * @param parser HTML parser to use
	 * @exception IOException if an error occurs in downloading the page
	 */
	public void download ( HTMLParser parser )
		throws IOException
	{
		URLConnection conn = SecurityPolicy.getPolicy().openConnection( origin );
		lastModified = conn.getLastModified();
		expiration = conn.getExpiration();
		contentType = conn.getContentType();
		contentEncoding = conn.getContentEncoding();
		// get HTTP response codes
		if ( conn instanceof HttpURLConnection ) {
			HttpURLConnection httpconn = (HttpURLConnection) conn;
			responseCode = httpconn.getResponseCode();
			responseMessage = httpconn.getResponseMessage();
			if ( responseMessage == null )
				responseMessage = "unknown error";
			if ( responseCode >= 300 )
				// HTTP failure
				throw new IOException( responseCode + " " + responseMessage );
		}
		// fetch and store final redirected URL and response headers
		base = conn.getURL();
		// download and parse the response
		InputStream in = conn.getInputStream();
		if ( contentType == null || contentType.startsWith( "text/html" ) || contentType.equals( "content/unknown" )
			 )
			parser.parse( this, in );
		else
			parser.dontParse( this, in );
		in.close();
		contentLock = 1;
	}

	void downloadSafely () {
		try {
			download( new HTMLParser() );
		} 
		catch ( Throwable e ) {}
	}

	//
	// Parsing
	//
	/** 
	 * Parse the page.  Assumes the page has already been downloaded.
	 * @param parser HTML parser to use
	 * @exception IOException if an error occurs in downloading the page
	 */
	public void parse ( HTMLParser parser ) {
		if ( !hasContent() )
			downloadSafely();
		try {
			parser.parse( this, _content );
		} 
		catch ( IOException e ) {
			throw new RuntimeException( e.toString() );
		}
	}

	/** 
	 * Test whether page has been parsed.  Pages are parsed during
	 * download only if its MIME type is HTML or unspecified.
	 * @return true if page was parsed, false if not
	 */
	public boolean isParsed () {
		return tokens != null;
	}

	/** 
	 * Test whether page is HTML.
	 * @return true if page is HTML, false if not
	 */
	public boolean isHTML () {
		return root != null;
	}
	/** 
	 * Test whether page is a GIF or JPEG image.
	 * @return true if page is a GIF or JPEG image, false if not
	 */
	private static final String GIF_CODE = "GIF8";
	private static final String JPG_CODE = "\377\330\377\340\0\020JFIF";

	public boolean isImage () {
		return _content.startsWith( GIF_CODE ) || _content.startsWith( JPG_CODE );
	}

	//
	// Content management
	//
	/** 
	 * Lock the page's content (to prevent it from being discarded).
	 * This method increments a lock counter, representing all the
	 * callers interested in preserving the content.  The lock
	 * counter is set to 1 when the page is initially downloaded.
	 */
	public void keepContent () {
		if ( contentLock > 0 )
			++contentLock;
	}

	/** 
	 * Unlock the page's content (allowing it to be garbage-collected, to
	 * save space during a Web crawl).  This method decrements a lock counter.
	 * If the counter falls to
	 * 0 (meaning no callers are interested in the content),
	 * the content is released.  At least the following
	 * fields are discarded: content, tokens, tags, words, elements, and
	 * root.  After the content has been discarded, calling getContent()
	 * (or getTokens(), getTags(), etc.) will force the page to be downloaded
	 * again.  Hopefully the download will come from the cache, however.
	 * <P> Links are not considered part of the content, and are not subject to
	 * discarding by this method.  Also, if the page was created from a string
	 * (rather than by downloading), its content is not subject to discarding
	 * (since there would be no way to recover it).
	 */
	public void discardContent () {
		if ( contentLock == 0 ) // already discarded
			return ;
		if ( --contentLock > 0 ) // somebody else still has a lock on the content
			return ;
		if ( origin == null )
			return ; // without an origin, we'd have no way to recover this page
			//System.err.println ("discarding content of " + toDescription());
		_content = null;
		tokens = null;
		tags = null;
		words = null;
		elements = null;
		root = null;
		canonicalTags = null;
		// keep links, but isolate them from the element tree
		if ( links != null ) {
			for ( int i = 0; i < links.length; ++i ) 
				if ( links[ i ] instanceof Link )
					((Link) links[ i ]).discardContent();
		}
		// FIX: debugging only: disconnect this page from its parent
		//origin.page = null;
		//origin = null;
		contentLock = 0;
	}

	/** 
	 * Test if page content is available.
	 * @return true if content is downloaded and available, false if content has not been downloaded
	 * or has been discarded.
	 */
	public final boolean hasContent () {
		return contentLock != 0;
	}

	//
	// Page accessors
	//
	/** 
	 * Get depth of page in crawl.
	 * @return depth of page from root (depth of page is same as depth of its originating link)
	 */
	public int getDepth () {
		return origin != null ? origin.getDepth() : 0;
	}

	/** 
	 * Get the Link that points to this page.
	 * @return the Link object that was used to download this page.
	 */
	public Link getOrigin () {
		return origin;
	}

	/** 
	 * Get the base URL, relative to which the page's links were interpreted.
	 * The base URL defaults to the URL of the
	 * Link that was used to download the page.  If any redirects occur
	 * while downloading the page, the final location becomes the new base
	 * URL.  Lastly, if a <BASE> element is found in the page, that
	 * becomes the new base URL.
	 * @return the page's base URL.
	 */
	public URL getBase () {
		return base;
	}

	/** 
	 * Get the URL.
	 * @return the URL of the link that was used to download this page
	 */
	public URL getURL () {
		return origin != null ? origin.getURL() : null;
	}

	/** 
	 * Get the title of the page.
	 * @return the page's title, or null if the page hasn't been parsed.
	 */
	public String getTitle () {
		return title;
	}

	/** 
	 * Get the content of the page.
	 * @return the Page object, or null if the page hasn't been downloaded.
	 */
	public String getContent () {
		if ( !hasContent() )
			downloadSafely();
		return _content;
	}

	/** 
	 * Get the token sequence of the page.  Tokens are tags and whitespace-delimited text.
	 * @return token regions in the page, or null if the page hasn't been downloaded or parsed.
	 */
	public Region[] getTokens () {
		if ( !hasContent() )
			downloadSafely();
		return tokens;
	}

	/** 
	 * Get the tag sequence of the page.
	 * @return tags in the page, or null if the page hasn't been downloaded or parsed.
	 */
	public Tag[] getTags () {
		if ( !hasContent() )
			downloadSafely();
		return tags;
	}

	/** 
	 * Get the words in the page.  Words are whitespace- and tag-delimited text.
	 * @return words in the page, or null if the page hasn't been downloaded or parsed.
	 */
	public Text[] getWords () {
		if ( !hasContent() )
			downloadSafely();
		return words;
	}

	/** 
	 * Get the HTML elements in the page.  All elements in the page
	 * are included in the list, in the order they would appear in
	 * an inorder traversal of the HTML parse tree.
	 * @return HTML elements in the page ordered by inorder, or null if the page
	 * hasn't been downloaded or parsed.
	 */
	public Element[] getElements () {
		if ( !hasContent() )
			downloadSafely();
		return elements;
	}

	/** 
	 * Get the root HTML element of the page.
	 * @return first top-level HTML element in the page, or null
	 * if the page hasn't been downloaded or parsed.
	 */
	public Element getRootElement () {
		if ( !hasContent() )
			downloadSafely();
		return root;
	}

	/** 
	 * Get the links found in the page.
	 * @return links in the page, or null
	 * if the page hasn't been downloaded or parsed.
	 */
	public Link[] getLinks () {
		return links;
	}

	/** 
	 * Convert the link's URL to a String
	 * @return the URL represented as a string
	 */
	public String toURL () {
		return origin != null ? origin.toURL() : null;
	}

	/** 
	 * Generate a human-readable description of the page.
	 * @return a description of the link, in the form "title [url]".
	 */
	public String toDescription () {
		return (title != null && title.length() > 0 ? title + " " : "") + "[" + getURL() + "]";
	}

	/** 
	 * Get page containing the region.
	 * @return page containing the region
	 */
	public String toString () {
		return getContent();
	}

	/** 
	 * Get last-modified date of page.
	 * @return the date when the page was last modified, or 0 if not known.
	 * The value is number of seconds since January 1, 1970 GMT
	 */
	public long getLastModified () {
		return lastModified;
	}

	/** 
	 * Set last-modified date of page.
	 * @param last the date when the page was last modified, or 0 if not known.
	 * The value is number of seconds since January 1, 1970 GMT
	 */
	public void setLastModified ( long last ) {
		lastModified = last;
	}

	/** 
	 * Get expiration date of page.
	 * @return the expiration date of the page, or 0 if not known.
	 * The value is number of seconds since January 1, 1970 GMT.
	 */
	public long getExpiration () {
		return expiration;
	}

	/** 
	 * Set expiration date of page.
	 * @param expire the expiration date of the page, or 0 if not known.
	 * The value is number of seconds since January 1, 1970 GMT.
	 */
	public void setExpiration ( long expire ) {
		expiration = expire;
	}

	/** 
	 * Get MIME type of page.
	 * @return the MIME type of page, such as "text/html", or null if not known.
	 */
	public String getContentType () {
		return contentType;
	}

	/** 
	 * Set MIME type of page.
	 * @param type the MIME type of page, such as "text/html", or null if not known.
	 */
	public void setContentType ( String type ) {
		contentType = type;
	}

	/** 
	 * Get content encoding of page.
	 * @return the encoding type of page, such as "base-64", or null if not known.
	 */
	public String getContentEncoding () {
		return contentEncoding;
	}

	/** 
	 * Set content encoding of page.
	 * @param encoding the encoding type of page, such as "base-64", or null if not known.
	 */
	public void setContentEncoding ( String encoding ) {
		contentEncoding = encoding;
	}

	/** 
	 * Get response code returned by the Web server.  For list of
	 * possible values, see java.net.HttpURLConnection.
	 * @return response code, such as 200 (for OK) or 404 (not found).
	 * Code is -1 if unknown.
	 * @see java.net.HttpURLConnection
	 */
	public int getResponseCode () {
		return responseCode;
	}

	/** 
	 * Get response message returned by the Web server.
	 * @return response message, such as "OK" or "Not Found".  The response message is null if the page failed to be fetched or not known.
	 */
	public String getResponseMessage () {
		return responseMessage;
	}

	/** 
	 * Get raw content found in a region.
	 * @param start starting offset of region
	 * @param end ending offset of region
	 * @return raw HTML contained in the region
	 */
	public String substringContent ( int start, int end ) {
		return _content.substring( start, end );
	}

	/** 
	 * Get HTML found in a region.
	 * @param start starting offset of region
	 * @param end ending offset of region
	 * @return representation of region as HTML
	 */
	public String substringHTML ( int start, int end ) {
		String s = _content.substring( start, end );
		if ( !isHTML() ) {
			s = StringUtil.replace( s, "&", "&amp;" );
			s = StringUtil.replace( s, "<", "&lt;" );
			s = StringUtil.replace( s, ">", "&gt;" );
			s = "<PRE>" + s + "</PRE>";
		}
		return s;
	}

	/** 
	 * Get tagless text found in a region.
	 * Runs of whitespace and tags are reduced to a single space character.
	 * @param start starting offset of region
	 * @param end ending offset of region
	 * @return tagless text contained in the region
	 */
	public String substringText ( int start, int end ) {
		if ( words == null )
			return ""; // page is not parsed
			 // FIX: find some other mapping
		StringBuffer buf = new StringBuffer();
		for ( int j = findStart( words, start ); j < words.length; ++j ) {
			if ( words[ j ]._end > end ) {
				break;
			} else {
				if ( buf.length() > 0 )
					buf.append( ' ' );
				buf.append( words[ j ].toText() );
			}
		}
		return buf.toString();
	}

	/** 
	 * Get HTML tags found in a region.  Whitespace and text among the
	 * tags are deleted.
	 * @param start starting offset of region
	 * @param end ending offset of region
	 * @return tags contained in the region
	 */
	public String substringTags ( int start, int end ) {
		if ( tags == null )
			return ""; // page is not parsed
			 // FIX: find some other mapping
		StringBuffer buf = new StringBuffer();
		for ( int j = findStart( tags, start ); j < tags.length; ++j ) {
			if ( tags[ j ]._end > end ) {
				break;
			} else {
				if ( buf.length() > 0 )
					buf.append( ' ' );
				buf.append( _content.substring( tags[ j ]._start, tags[ j ]._end ) );
			}
		}
		return buf.toString();
	}

	/** 
	 * Get canonicalized HTML tags found in a region.
	 * A canonicalized tag looks like the following:
	 * <PRE>
	 * &lt;tagname#index attr=value attr=value attr=value ...&gt
	 * <PRE>
	 * where tagname and attr are all lowercase, index is the tag's
	 * index in the page's tokens array.  Attributes are sorted in
	 * increasing order by attribute name. Attributes without values
	 * omit the entire "=value" portion.  Values are delimited by a
	 * space.  All occurences of &lt, &gt, space, and % characters
	 * in a value are URL-encoded (e.g., space is converted to %20).
	 * Thus the only occurences of these characters in the canonical
	 * tag are the tag delimiters.
	 * 
	 * <P>For example, raw HTML that looks like:
	 * <PRE>
	 * &lt;IMG SRC="http://foo.com/map&lt;&gt;.gif" ISMAP&gt;Image&lt;/IMG&gt;
	 * </PRE>
	 * would be canonicalized to:
	 * <PRE>
	 * &lt;img ismap src=http://foo.com/map%3C%3E.gif&gt;&lt;/img&gt;
	 * </PRE>
	 * <P>
	 * Comment and declaration tags (whose tag name is !) are omitted
	 * from the canonicalization.
	 * 
	 * @param start starting offset of region
	 * @param end ending offset of region
	 * @return canonicalized tags contained in the region
	 */
	public String substringCanonicalTags ( int start, int end ) {
		if ( tokens == null )
			return ""; // page is not parsed
			 boolean all = (start == _start && end == _end);
		if ( all && canonicalTags != null )
			return canonicalTags;
		// FIX: find some other mapping
		StringBuffer buf = new StringBuffer();
		for ( int j = findStart( tokens, start ); j < tokens.length; ++j ) {
			if ( tokens[ j ]._end > end )
				break;
			else 
			if ( tokens[ j ] instanceof Tag )
				TagExp.canonicalizeTag( buf, (Tag) tokens[ j ], j );
		}
		String result = buf.toString();
		if ( all )
			canonicalTags = result;
		return result;
	}

	public static void main ( String[] args )
		throws Exception
	{
		int method = Link.GET;
		for ( int i = 0; i < args.length; ++i ) {
			if ( args[ i ].equals( "-post" ) )
				method = Link.POST;
			else 
			if ( args[ i ].equals( "-get" ) ) {
				method = Link.GET;
			} else {
				Link link = method == Link.GET ? new Link( args[ i ] ) : new Link( args[ i ] ); // FIX: POST?
				try {
					System.out.print( new Page( link ).getContent() );
				} 
				catch ( IOException e ) {
					System.out.println( e );
				}
			}
		}
	}
}

