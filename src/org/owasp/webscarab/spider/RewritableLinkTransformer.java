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
import java.io.RandomAccessFile;
import java.io.IOException;
import java.net.URL;

/** 
 * Transformer that remaps URLs in links in such a way
 * that if the URL mapping changes during (or after) some
 * HTML has been transformed, the HTML can be fixed up after
 * the fact.  This class is used by Concatenator and Mirror,
 * since in those operations, the URL mapping function
 * changes as each page is written to the concatenation or
 * mirror.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class RewritableLinkTransformer 
	extends LinkTransformer 
{
	private RewriteRegion head,  tail;
	private File file;
	private boolean closed = false;
	
	/** 
	 * Make a RewritableLinkTransformer.
	 * @param filename Filename to write to
	 */
	public RewritableLinkTransformer ( String filename )
		throws IOException
	{
		super( filename, true );
		file = new File( filename );
	}

	public void close ()
		throws IOException
	{
		super.close();
		closed = true;
	}
	static final String PLACEHOLDER = "@WEBSPHINX@";

	protected void handleLink ( Link link )
		throws IOException
	{
		URL url = link.getURL();
		Tag t = link.replaceHref( PLACEHOLDER );
		String s = t.toString();
		int prefix = s.indexOf( PLACEHOLDER );
		if ( prefix != -1 ) {
			int postfix = prefix + PLACEHOLDER.length();
			emit( s.substring( 0, prefix ) );
			String href = lookup( _base, url );
			RewriteRegion node = addURL( url, getFilePointer(), href.length() );
			emit( href );
			emit( s.substring( postfix ) );
		} else {
			emit( s );
		}
		transformContents( link );
		if ( link.getEndTag() != null )
			emit( link.getEndTag() );
	}

	private RewriteRegion addURL ( URL url, long offset, int len ) {
		RewriteRegion node = new RewriteRegion();
		node.url = url;
		node.offset = offset;
		node.len = len;
		if ( tail == null ) {
			head = tail = node;
		} else {
			node.next = tail.next;
			tail.next = node;
			node.prev = tail;
			if ( node.next != null )
				node.next.prev = node;
			tail = node;
		}
		return node;
	}
	static final int BUFFER_SIZE = 8;

	/** 
	 * Rewrite the file, remapping all the URLs according to their
	 * current values from lookup().
	 */
	public void rewrite ()
		throws IOException
	{
		flush();
		if ( head == null )
			// no links to rewrite
			return ;
		RandomAccessFile raf = closed ? SecurityPolicy.getPolicy().readWriteFile( file ) : getRandomAccessFile();
		byte[] buf = new byte[BUFFER_SIZE];
		long end = raf.length();
		long src = 0;
		long dest = 0;
		long left;
		int n;
		int growth = 0;
		int shrinkage = 0;
		// Forward pass
		//    Rewrite only URLs which are becoming shorter
		raf.seek( dest );
		for ( RewriteRegion loc = head; loc != null; loc = loc.next ) {
			// loop invariant: file[0..dest-1] is rewritten,
			// and next byte to copy to file[dest] is from file[src]
			// and raf.getFilePointer() == dest
			long diff = dest - src;
			String href = lookup( _base, loc.url );
			loc.newHref = href;
			loc.newLen = href.length();
			if ( loc.newLen > loc.len ) {
				// new URL is longer than old URL
				// must postpone rewriting this until the backward pass
				growth += loc.newLen - loc.len;
				loc.offset += diff;
				continue;
			} else {
				shrinkage += loc.len - loc.newLen;
			}
			// rewrite up to loc
			left = loc.offset - src;
			while ( left > BUFFER_SIZE ) {
				raf.seek( src );
				raf.read( buf );
				raf.seek( dest );
				raf.write( buf );
				src += BUFFER_SIZE;
				dest += BUFFER_SIZE;
				left -= BUFFER_SIZE;
			}
			if ( left > 0 ) {
				n = (int) left;
				raf.seek( src );
				raf.read( buf, 0, n );
				raf.seek( dest );
				raf.write( buf, 0, n );
				src += n;
				dest += n;
				left -= n;
			}
			// write loc
			raf.writeBytes( href );
			dest += loc.newLen;
			src += loc.len;
			loc.offset += diff;
			loc.len = loc.newLen;
		}
		if ( src > dest ) {
			// rewrite rest of file
			while ( true ) {
				raf.seek( src );
				if ( (n = raf.read( buf )) == -1 )
					break;
				raf.seek( dest );
				raf.write( buf, 0, n );
				src += n;
				dest += n;
			}
		} else {
			src = dest = end;
		}
		src = dest;
		dest += growth;
		for ( RewriteRegion loc = tail; loc != null; loc = loc.prev ) {
			// loop invariant: file[dest...end-1] is rewritten,
			// and next byte to copy to file[dest] is from file[src]
			long diff = dest - src;
			if ( loc.newLen <= loc.len ) {
				loc.offset += diff;
				continue;
			}
			// rewrite back to loc
			left = src - (loc.offset + loc.len);
			while ( left > BUFFER_SIZE ) {
				src -= BUFFER_SIZE;
				dest -= BUFFER_SIZE;
				left -= BUFFER_SIZE;
				raf.seek( src );
				raf.read( buf );
				raf.seek( dest );
				raf.write( buf );
			}
			if ( left > 0 ) {
				n = (int) left;
				src -= n;
				dest -= n;
				raf.seek( src );
				raf.read( buf, 0, n );
				raf.seek( dest );
				raf.write( buf, 0, n );
			}
			// write loc
			dest -= loc.newLen;
			src -= loc.len;
			raf.seek( dest );
			raf.writeBytes( loc.newHref );
			loc.offset = dest;
			loc.len = loc.newLen;
		}
		if ( src != dest )
			System.err.println( "ASSERTION FAILURE: src=" + src + "!=dest=" + dest );
		if ( shrinkage > growth ) {
			// overwrite the rest of the file with spaces
			for ( int i = 0; i < BUFFER_SIZE; ++i ) 
				buf[ i ] = (byte) ' ';
			left = shrinkage - growth;
			raf.seek( end - left );
			while ( left > BUFFER_SIZE ) {
				raf.write( buf );
				left -= BUFFER_SIZE;
			}
			if ( left > 0 )
				raf.write( buf, 0, (int) left );
		} else {
			raf.seek( end + (growth - shrinkage) );
		}
		if ( closed )
			raf.close();
	}
/* 
 * Testing
 * 
 * public static void main (String[] args) throws Exception {
 * RewritableLinkTransformer unparser = new TestILTransformer (args[1]);
 * Link link = new Link (args[0]);
 * Page page = new Page (link);
 * System.out.println ("Writing " + page.toDescription());
 * unparser.writePage (page);
 * System.out.println ("Rewriting while open");
 * unparser.rewrite ();
 * unparser.close ();
 * System.out.println ("Rewriting after close");
 * unparser.rewrite ();
 * }
 */
}

