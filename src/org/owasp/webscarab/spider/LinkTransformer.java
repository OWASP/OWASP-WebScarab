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

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.Hashtable;

/** 
 * Transformer that remaps URLs in links.
 * <P>
 * The default LinkTransformer simply converts all links
 * to absolute URLs.  Other common effects are easy to
 * achieve:
 * <UL>
 * <LI>To make all links relative to a base URL, use
 * setBase() to set a base URL.
 * <LI>To replace certain URLs with different ones,
 * use map() to set up the mappings.
 * </UL>
 * The default LinkTransformer strips out &lt;BASE&gt;
 * elements.  Instead, it can output a &lt;BASE&gt;
 * element with a user-specified URL.  Use setBase() to set
 * the URL and setEmitBaseElement() to indicate that it
 * should be emitted.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class LinkTransformer 
	extends HTMLTransformer 
{
	protected Hashtable _map;
	protected URL _base;
	protected boolean _emitBaseElement;
	protected boolean _needToEmitBase;
	
	/** 
	 * Make a LinkTransformer writing to a file.
	 * @param filename Filename to write to
	 */
	public LinkTransformer ( String filename )
		throws IOException
	{
		this( filename, false );
	}
	
	/** 
	 * Make a LinkTransformer that writes pages to a
	 * file.
	 * @param filename Name of file to receive HTML output
	 * @param seekable True if file should be opened for random access
	 */
	public LinkTransformer ( String filename, boolean seekable )
		throws IOException
	{
		super( filename, seekable );
		_map = null;
		_base = null;
		_emitBaseElement = false;
		_needToEmitBase	= false;
	}
	
	/** 
	 * Make a LinkTransformer writing to a stream.
	 * @param out stream to write to
	 */
	public LinkTransformer ( OutputStream out ) {
		super( out );
	}
	
	public LinkTransformer ( Writer writer ) {
		super( writer );
	}
	
	/** 
	 * Make a LinkTransformer writing to another HTMLTransformer
	 * @param next next transformer in filter chain
	 */
	public LinkTransformer ( HTMLTransformer next ) {
		super( next );
	}

	/** 
	 * Get the base URL used by the LinkTransformer.
	 * A transformed link's URL is written out relative
	 * to this URL.  For instance, if the base URL is
	 * http://www.yahoo.com/Entertainment/, then a link
	 * URL http://www.yahoo.com/News/Current/
	 * would be written out as ../News/Current/.
	 * @return base URL, or null if no base URL is set.  Default is null.
	 */
	public URL getBase () {
		return _base;
	}

	/** 
	 * Set the base URL used by the LinkTransformer.
	 * A transformed link's URL is written out relative
	 * to this URL.  For instance, if the base URL is
	 * http://www.yahoo.com/Entertainment/, then a link
	 * URL http://www.yahoo.com/News/Current/
	 * would be written out as ../News/Current/.
	 * @param base base URL, or null if no base URL should be used.
	 */
	public synchronized void setBase ( URL base ) {
		_base = base;
	}

	/** 
	 * Test whether the LinkTransformer should emit a
	 * &lt;BASE&gt; element pointing to the base URL.
	 * @return true if a &lt;BASE&gt; element should be
	 * emitted with each page.
	 */
	public boolean getEmitBaseElement () {
		return _emitBaseElement;
	}

	/** 
	 * Set whether the LinkTransformer should emit a
	 * &lt;BASE&gt; element pointing to the base URL.
	 * @param emitBase true if a &lt;BASE&gt; element should be
	 * emitted with each page.
	 */
	public synchronized void setEmitBaseElement ( boolean emitBase ) {
		_emitBaseElement = emitBase;
	}

	/** 
	 * Look up the href for a URL, taking any mapping
	 * into account.
	 * @param base base URL (or null if an absolute URL is desired)
	 * @param url URL of interest
	 * @return relative href for url from base
	 */
	public String lookup ( URL base, URL url ) {
		if ( null != _map  ) {
			Object obj = _map.get( url );
			if ( obj instanceof URL )
				return null != _base ? Link.relativeTo( _base, (URL) obj ) : obj.toString();
			else 
			if ( obj instanceof String )
				return null != _base ? Link.relativeTo( _base, (String) obj ) : obj.toString();
		}
		return null != _base ? Link.relativeTo( _base, url ) : url.toString();
	}

	/** 
	 * Map a URL to an href.  For example, Concatenator
	 * uses this call to map page URLs to their corresponding
	 * anchors in the concatenation.
	 * @param url URL of interest
	 * @param href href which should be returned by lookup (null, url)
	 */
	public synchronized void map ( URL url, String href ) {
		if ( null == _map )
			_map = new Hashtable();
		_map.put( url, href );
	}

	/** 
	 * Map a URL to a new URL.  For example, Mirror
	 * uses this call to map remote URLs to their corresponding
	 * local URLs.
	 * @param url URL of interest
	 * @param newURL URL which should be returned by lookup (null, url)
	 */
	public synchronized void map ( URL url, URL newURL ) {
		if ( null == _map )
			_map = new Hashtable();
		_map.put( url, newURL );
	}

	/** 
	 * Test whether a URL is mapped.
	 * @param url URL of interest
	 * @return true if map () was called to remap url
	 */
	public boolean isMapped ( URL url ) {
		return null != _map && _map.containsKey( url );
	}

	/** 
	 * Write a page through the transformer.  If
	 * getEmitBaseElement() is true and getBase() is
	 * non-null, then the transformer
	 * outputs a &lt;BASE&gt; element either inside the
	 * page's &lt;HEAD&gt; element (if present) or before
	 * the first tag that belongs in &lt;BODY&gt;.
	 * @param page Page to write
	 */
	public synchronized void writePage ( Page page )
		throws IOException
	{
		_needToEmitBase = _emitBaseElement && null != _base;
		super.writePage( page );
		_needToEmitBase = false;
	}

	/** 
	 * Handle an element written through the transformer.
	 * Remaps attributes that contain URLs.
	 * @param elem Element to transform
	 */
	protected void handleElement ( Element elem )
		throws IOException
	{
		Tag tag = elem.getStartTag();
		String tagName = elem.getTagName();
		if ( _needToEmitBase && tag.isBodyTag() ) {
			emit( "<BASE HREF=\"" + _base.toString() + "\">" );
			_needToEmitBase = false;
		}
		if ( elem instanceof Link )
			handleLink( (Link) elem );
		else 
		if ( tagName == Tag.BASE )
			handleBase( elem );
		else 
		if ( _needToEmitBase && Tag.HEAD == tagName ) {
			// put BASE at the end of HEAD, if we don't find it earlier
			emit( elem.getStartTag() );
			transformContents( elem );
			if ( _needToEmitBase ) {
				emit( "<BASE HREF=\"" + _base.toString() + "\">" );
				_needToEmitBase = false;
			}
			if ( elem.getEndTag() != null )
				emit( elem.getEndTag() );
		} else {
			super.handleElement( elem );
		}
	}

	/** 
	 * Handle a Link's transformation.
	 * Default implementation replaces the link's URL
	 * with lookup(URL).
	 * @param link Link to transform
	 */
	protected void handleLink ( Link link )
		throws IOException
	{
		emit( link.replaceHref( lookup( _base, link.getURL() ) ) );
		transformContents( link );
		if ( link.getEndTag() != null )
			emit( link.getEndTag() );
	}

	/** 
	 * Handle the BASE element.
	 * Default implementation removes if if EmitBaseElement
	 * is false, or changes its URL to Base if EmitBaseElement
	 * is true.
	 * @param elem BASE element to transform
	 */
	protected void handleBase ( Element elem )
		throws IOException
	{
		Tag tag = elem.getStartTag();
		if ( _needToEmitBase ) {
			emit( tag.replaceHTMLAttribute( "href", _base.toString() ) );
			_needToEmitBase = false;
		} else {
			if ( tag.hasHTMLAttribute( "href" ) && tag.countHTMLAttributes() > 1 )
				// tag has other attributes that we want to preserve
				emit( tag.removeHTMLAttribute( "href" ) );
		}
	// otherwise skip the BASE element
	}
/* 
 * Testing
 * 
 * public static void main (String[] args) throws Exception {
 * OutputStream out = (args.length >= 2)
 * ? (OutputStream)new java.io.FileOutputStream (args[1])
 * : (OutputStream)System.out;
 * HTMLTransformer unparser = new LinkTransformer (out);
 * Link link = new Link (args[0]);
 * Page page = new Page (link);
 * unparser.write (page);
 * unparser.close ();
 * }
 */
}

