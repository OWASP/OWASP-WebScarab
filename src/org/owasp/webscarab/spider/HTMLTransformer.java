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
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.io.Writer;
import java.io.OutputStreamWriter;

/** 
 * HTML filter that can be used together with other filters in a filter chain.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class HTMLTransformer {
	/** output writer */
	private Writer _writer;
	/** flag whether the writer is open */
	private boolean _openedWriter = false;
	/** output file */
	private RandomAccessFile _readwrite;
	/** next HTMLTransformer in the filter chain */
	private HTMLTransformer _next;
	/** head of filter chain */
	private HTMLTransformer _head;
	/** tail of filter chain */
	private HTMLTransformer _tail;
	// these fields are only valid on the tail element in the filter
	// chain
	/** content of page being printed */
	private String _content;
	/** start of pending region */
	private int _emitStart;
	/** end of pending region */
	private int _emitEnd;
	//   (the last region in the page which
	//    has been emit()ed but not actually
	//    written)
	/** end of region being transformed */
	private int _transformEnd;
	
	/** 
	 * Make an HTMLTransformer that writes pages to a
	 * stream.
	 * @param out Stream to receive HTML output
	 */
	public HTMLTransformer ( OutputStream out ) {
		_head = this;
		_tail = this;
		_next = null;
		setOutput( out );
	}
	
	/** 
	 * Make an HTMLTransformer that writes pages to a
	 * file.
	 * @param filename Name of file to receive HTML output
	 * @exception IOException if file cannot be opened
	 */
	public HTMLTransformer ( String filename )
		throws IOException
	{
		this( filename, false );
	}
	
	/** 
	 * Make an HTMLTransformer that writes pages to a
	 * file.
	 * @param filename Name of file to receive HTML output
	 * @param seekable True if file should be opened for random access
	 */
	public HTMLTransformer ( String filename, boolean seekable )
		throws IOException
	{
		_head = this;
		_tail = this;
		_next = null;
		openFile( filename, seekable );
	}
	
	/** 
	 * Make an HTMLTransformer that writes pages to a
	 * Writer.
	 * @param writer Writer to receive HTML output
	 */
	public HTMLTransformer ( Writer writer ) {
		_head = this;
		_tail = this;
		_next = null;
		setOutput( writer );
	}
	
	/** 
	 * Make an HTMLTransformer that writes pages to a
	 * downstream HTMLTransformer.  Use this constructor
	 * to chain together several HTMLTransformers.
	 * @param next HTMLTransformer to receive HTML output
	 */
	public HTMLTransformer ( HTMLTransformer next ) {
		_next = next;
		_tail = null != _next ? _next._tail : this;
		for ( HTMLTransformer u = this; null != u; u = u._next ) 
			u._head = this;
	}

	private void openFile ( String filename, boolean seekable )
		throws IOException
	{
		File file = new File( filename );
		// open a stream first, to truncate the file to 0
		OutputStream out = SecurityPolicy.getPolicy().writeFile( file, false );
		if ( !seekable ) {
			setOutput( out );
		} else {
			out.close();
			RandomAccessFile raf = SecurityPolicy.getPolicy().readWriteFile( file );
			setRandomAccessFile( raf );
		}
		_openedWriter = true;
	}

	public void setOutput ( OutputStream out ) {
		if ( null == _next )
			_writer = new OutputStreamWriter( out );
		else
			_next.setOutput( out );
	}

	public void setOutput ( Writer out ) {
		if ( null == _next )
			_writer = out;
		else
			_next.setOutput( out );
	}

	public Writer getOutput () {
		return _tail._writer;
	}

	public void setRandomAccessFile ( RandomAccessFile raf ) {
		if ( null == _next )
			_readwrite = raf;
		else
			_next.setRandomAccessFile( raf );
	}

	public RandomAccessFile getRandomAccessFile () {
		return _tail._readwrite;
	}

	/** 
	 * Writes a literal string through the HTML transformer
	 * (without parsing it or transforming it).
	 * @param string String to write
	 */
	public synchronized void write ( String string )
		throws IOException
	{
		if ( null == _next )
			emit( string );
		else
			_next.write( string );
	}

	/** 
	 * Writes a chunk of HTML through the HTML transformer.
	 * @param region Region to write
	 */
	public synchronized void write ( Region region )
		throws IOException
	{
		if ( null == _next ) {
			emitPendingRegion();
			String oldContent = _content;
			int oldEmitStart = _emitStart;
			int oldEmitEnd = _emitEnd;
			int oldTransformEnd = _transformEnd;
			_content = region.getSource().getContent();
			_emitStart = region.getStart();
			_emitEnd = _emitStart;
			_transformEnd = region.getEnd();
			processElementsInRegion( region.getRootElement(), region.getStart(), region.getEnd() );
			emitPendingRegion();
			_content = oldContent;
			_emitStart = oldEmitStart;
			_emitEnd = oldEmitEnd;
			_transformEnd = oldTransformEnd;
		} else {
			_next.write( region );
		}
	}

	/** 
	 * Writes a page through the HTML transformer.
	 * @param page Page to write
	 */
	public synchronized void writePage ( Page page )
		throws IOException
	{
		if ( null == _next ) {
			write( page );
		} else {
			_next.writePage( page );
		}
	}

	/** 
	 * Flushes transformer to its destination stream.
	 * Empties any buffers in the transformer chain.
	 */
	public synchronized void flush ()
		throws IOException
	{
		if ( null == _next ) {
			emitPendingRegion();
			if ( null != _writer )
				_writer.flush();
		} else {
			_next.flush();
		}
	}

	/** 
	 * Close the transformer.  Flushes all buffered data
	 * to disk by calling flush().  This call may be
	 * time-consuming!  Don't use the transformer again after
	 * closing it.
	 * @exception IOException if an I/O error occurs
	 */
	public synchronized void close ()
		throws IOException
	{
		flush();
		if ( null == _next ) {
			if ( _openedWriter ) {
				if ( null != _writer )
					_writer.close();
				if ( null != _readwrite )
					_readwrite.close();
			}
		} else {
			_next.close();
		}
	}

	/** * Finalizes the transformer (calling close()). */
	protected void finalize ()
		throws Throwable
	{
		close();
	}

	/** 
	 * Get the file pointer.
	 * @return current file pointer
	 * @exception IOException if this transformer not opened for random access
	 */
	public long getFilePointer ()
		throws IOException
	{
		if ( null == _readwrite )
			throw new IOException( "HTMLTransformer not opened for random access" );
		return _readwrite.getFilePointer();
	}

	/** 
	 * Seek to a file position.
	 * @param pos file position to seek
	 * @exception IOException if this transformer not opened for random access
	 */
	public void seek ( long pos )
		throws IOException
	{
		if ( null == _readwrite )
			throw new IOException( "HTMLTransformer not opened for random access" );
		_readwrite.seek( pos );
	}

	/** 
	 * Transform an element by passing it through the entire
	 * filter chain.
	 * @param elem Element to be transformed
	 */
	protected void transformElement ( Element elem )
		throws IOException
	{
		_head.handleElement( elem );
	}

	/** 
	 * Transform the contents of an element.  Passes
	 * the child elements through the filter chain
	 * and emits the text between them.
	 * @param elem Element whose contents should be transformed
	 */
	protected void transformContents ( Element elem )
		throws IOException
	{
		Tag startTag = elem.getStartTag();
		Tag endTag = elem.getEndTag();
		_tail.processElementsInRegion( elem.getChild(), startTag.getEnd(),
			null != endTag ? endTag.getStart() : elem.getEnd() );
	}

	/** 
	 * Handle the transformation of an HTML element.
	 * Override this method to modify the HTML as it is
	 * written.
	 * @param elem Element to transform
	 */
	protected void handleElement ( Element elem )
		throws IOException
	{
		if ( null == _next ) {
			Tag startTag = elem.getStartTag();
			Tag endTag = elem.getEndTag();
			emit( startTag );
			transformContents( elem );
			if ( endTag != null )
				emit( endTag );
		} else {
			_next.handleElement( elem );
		}
	}

	/** 
	 * Emit a region on the transformer chain's final output.
	 * (The region isn't passed through the chain.)
	 * @param r Region to emit
	 */
	protected void emit ( Region r )
		throws IOException
	{
		_tail.emitInternal( r.getSource().getContent(), r.getStart(), r.getEnd() );
	}

	/** 
	 * Emit a string on the transformer chain's final output.
	 * @param string String to emit
	 */
	protected void emit ( String string )
		throws IOException
	{
		_tail.emitInternal( string, 0, string.length() );
	}

	private void processElementsInRegion ( Element elem, int start, int end )
		throws IOException
	{
		if ( this != _tail )
			throw new RuntimeException( "processElementsInRegion not called on tail" );
		int p = start;
		if ( null != elem && elem.getSource().getContent() == _content )
			end = Math.min( end, _transformEnd );
		while ( elem != null && elem.getStartTag().getEnd() <= end ) {
			emitInternal( _content, p, elem.getStart() );
			transformElement( elem );
			p = elem.getEnd();
			elem = elem.getNext();
		}
		emitInternal( _content, Math.min( p, end ), end );
	}

	private void emitInternal ( String str, int start, int end )
		throws IOException
	{
		if ( this != _tail )
			throw new RuntimeException( "emitInternal not called on tail" );
		if ( str == _content ) {
			start = Math.min( start, _transformEnd );
			end = Math.min( end, _transformEnd );
			if ( start == _emitEnd ) {
				// just extend the pending emit region
				_emitEnd = end;
			} else {
				emitPendingRegion();
				_emitStart = start;
				_emitEnd = end;
			}
		} else {
			emitPendingRegion();
			doWrite( str.substring( start, end ) );
		}
	}

	private void emitPendingRegion ()
		throws IOException
	{
		if ( this != _tail )
			throw new RuntimeException( "emitPendingRegion not called on tail" );
		if ( _emitStart != _emitEnd ) {
			doWrite( _content.substring( _emitStart, _emitEnd ) );
			_emitStart = _emitEnd;
		}
	}

	private void doWrite ( String s )
		throws IOException
	{
		if ( null != _writer ) {
			_writer.write( s );
		} else {
			_readwrite.writeBytes( s );
		}
	}
/* 
 * Testing
 * 
 * public static void main (String[] args) throws Exception {
 * Link link = new Link (args[0]);
 * Page page = new Page (link);
 * OutputStream out = (args.length >= 2)
 * ? (OutputStream)new java.io.FileOutputStream (args[1])
 * : (OutputStream)System.out;
 * HTMLTransformer unparser = new TestTransformer (out);
 * int len = page.getLength();
 * unparser.write (new Region (page, 0, 3*len/4));
 * 
 * unparser.close ();
 * }
 */
}

