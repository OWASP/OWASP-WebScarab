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
import java.io.IOException;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.Hashtable;
import org.owasp.util.StringUtil;

/** 
 * Transformer that concatenates multiple pages
 * into a single HTML page.
 * <P>
 * The entire set of pages is preceded by a "prolog"
 * and followed by an "epilog", which are constant
 * strings of HTML.  Each page is preceded
 * by a "header" and followed by a "footer".  Adjacent pages
 * are separated by a "divider".
 * <P>
 * Concatenator performs the following
 * transformations on pages before appending them together:
 * <UL>
 * <LI> deletes elements that would conflict, including
 * &lt;HEADf&gt;, &lt;TITLEf&gt;, &lt;BODYf&gt;, &lt;HTMLf&gt,
 * &lt;STYLE&gt;, and &lt;FRAMES&gt;.
 * <LI> deletes &lt;BASEf&gt; or replaces it with a user-specified
 * &lt;BASEf&gt;
 * <LI> changes links among the written pages into
 * in-page references, of the form "#concatenator_N"
 * <LI> changes links to other pages into absolute references
 * </UL>
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
// FIXME: transform anchors
public class Concatenator 
	extends RewritableLinkTransformer 
{
	boolean _needRewrite = false;
	public static final String DFLT_PROLOG = "<HTML><HEAD><TITLE>Concatenation</TITLE></HEAD><BODY>\n";
	public static final String DFLT_HEADER = "<TABLE WIDTH=\"100%\"><TR>\n" 
		+ "<TD ALIGN=left><A NAME=\"%a\">%t [%u]</A>\n"
		+ "<TD ALIGN=right>Page %p</TABLE>\n";
	public static final String DFLT_FOOTER = "";
	public static final String DFLT_DIVIDER = "\n<DIV STYLE=\"page-break-after: always;\"><HR></DIV>\n";
	public static final String DFLT_EPILOG = "\n</BODY></HTML>\n";
	protected String _prolog;
	protected String _header;
	protected String _footer;
	protected String _divider;
	protected String _epilog;
	protected int _nPages; 
	
	/** 
	 * Make a new Concatenator that writes to a file.
	 * @param filename Filename to write concatenated pages to
	 * @exception IOException if file cannot be opened
	 */
	public Concatenator ( String filename )
		throws IOException
	{
		super( makeDirs( filename ) );
		_prolog = DFLT_PROLOG;
		_header = DFLT_HEADER;
		_footer = DFLT_FOOTER;
		_divider = DFLT_DIVIDER;
		_epilog = DFLT_EPILOG;
		_nPages = 0;
	}

	private static String makeDirs ( String filename )
		throws IOException
	{
		File file = new File( filename );
		File parent = new File( file.getParent() );
		if ( parent != null )
			SecurityPolicy.getPolicy().makeDir( parent );
		return filename;
	}

	/** 
	 * Set the prolog.
	 * @param prolog string of HTML that is emitted at the beginning
	 * of the concatenation. Default value is: <br>
	 * <code>&lt;HTML&gt;&lt;HEAD&gt;&lt;TITLE&gt;Concatenation&lt;/TITLE&gt;&lt;/HEAD&gt;&lt;BODY&gt;\n</code>
	 */
	public synchronized void setProlog ( String prolog ) {
		_prolog = prolog;
	}

	/** 
	 * Get the prolog.
	 * @return string of HTML that is emitted at the beginning
	 * of the concatenation.
	 */
	public String getProlog () {
		return _prolog;
	}

	/** 
	 * Set the header.  The header can contain macro codes which
	 * are replaced with attributes of the page about to be written:
	 * <dl>
	 * <dt>%t
	 * <dd>title of the page
	 * <dt>%u
	 * <dd>URL of page
	 * <dt>%a
	 * <dd>anchor name of the page ("pageN", where N is the page number)
	 * <dt>%p
	 * <dd>page number (starting from 1)
	 * </dl>
	 * @param header string of HTML that is emitted before
	 * each page. The default value is:<br>
	 * <code> &lt;TABLE WIDTH="100%"&gt;&lt;TR&gt;\n <br>
	 * &lt;TD ALIGN=left&gt;&lt;A NAME="%a"&gt;%t [%u]&lt;/A&gt;\n <br>
	 * &lt;TD ALIGN=right&gt;Page %p&lt;/TABLE&gt;\n</code>
	 */
	public synchronized void setPageHeader ( String header ) {
		_header = header;
	}

	/** 
	 * Get the header.
	 * @return string of HTML that is emitted before
	 * each page.
	 */
	public String getPageHeader () {
		return _header;
	}

	/** 
	 * Set the footer.  The footer can contain the same
	 * macros as the header (%t, %u, %a, %p); see setPageHeader
	 * for more details.
	 * @param footer string of HTML that is emitted after
	 * each page.
	 */
	public synchronized void setPageFooter ( String footer ) {
		_footer = footer;
	}

	/** 
	 * Get the footer.
	 * @return string of HTML that is emitted after
	 * each page.
	 */
	public String getPageFooter () {
		return _footer;
	}

	/** 
	 * Set the divider.
	 * @param divider string of HTML that is emitted between
	 * each pair of pages.
	 */
	public synchronized void setDivider ( String divider ) {
		_divider = divider;
	}

	/** 
	 * Get the divider.
	 * @return string of HTML that is emitted between
	 * each pair of pages.
	 */
	public String getDivider () {
		return _divider;
	}

	/** 
	 * Set the epilog.
	 * @param epilog string of HTML that is emitted after
	 * the entire concatenation.
	 */
	public synchronized void setEpilog ( String epilog ) {
		_epilog = epilog;
	}

	/** 
	 * Get the epilog.
	 * @return string of HTML that is emitted after
	 * the entire concatenation.
	 */
	public String getEpilog () {
		return _epilog;
	}

	/** 
	 * Get number of pages written to this mirror.
	 * @return number of calls to writePage() on this mirror
	 */
	public synchronized int getPageCount () {
		return _nPages;
	}

	/** 
	 * Rewrite the concatenation.  Makes sure all the links
	 * among concatenated pages have been fixed up.
	 */
	public synchronized void rewrite ()
		throws IOException
	{
		if ( _needRewrite ) {
			super.rewrite();
			_needRewrite = false;
		}
	}

	/** 
	 * Close the concatenation.  Makes sure all the links
	 * among concatenated pages have been fixed up and closes
	 * the file.
	 */
	public synchronized void close ()
		throws IOException
	{
		if ( 0 == _nPages )
			write( _prolog );
		emit( _epilog );
		rewrite();
		super.close();
	}

	/** 
	 * Write a page to the concatenation.
	 * @param page Page to write
	 */
	public synchronized void writePage ( Page page )
		throws IOException
	{
		++_nPages;
		emit( ( 1 == _nPages) ? _prolog : _divider );
		String title = page.getTitle();
		URL url = page.getURL();
		String urlString = url.toExternalForm();
		String anchor = "page" + _nPages;
		map( url, "#" + anchor );
		emitTemplate( _header, title, urlString, anchor, _nPages );
		if ( page.isImage() && page.getURL() != null )
			super.write( "<IMG SRC='" + page.getURL() + "'>" );
		else 
		if ( page.isHTML() )
			// it's HTML, can write it normally
			super.writePage( page );
		else
			super.write( page.toHTML() );
		emitTemplate( _footer, title, urlString, anchor, _nPages );
		_needRewrite = _nPages > 1;
	}

	private void emitTemplate ( String tpl, String title, String url, String anchor, int pages )
		throws IOException
	{
		if ( tpl == null || tpl.length() == 0 )
			return ;
		tpl = StringUtil.replace( tpl, "%t", title != null ? title : "" );
		tpl = StringUtil.replace( tpl, "%u", url != null ? url : "" );
		tpl = StringUtil.replace( tpl, "%a", anchor != null ? anchor : "" );
		tpl = StringUtil.replace( tpl, "%p", String.valueOf( pages ) );
		emit( tpl );
	}

	/** 
	 * Process an HTML element for concatenation.  Deletes
	 * tags that would
	 * conflict with other pages (such as &lt;HEAD&gt;),
	 * changes the URLs in Link elements, and deletes
	 * or remaps the BASE element.
	 * @param elem HTML element to process
	 */
	protected void handleElement ( Element elem )
		throws IOException
	{
		String name = elem.getTagName();
		if ( name == Tag.TITLE || name == Tag.STYLE || name == Tag.BASE || name == Tag.ISINDEX || name == Tag.FRAMESET
			|| name == Tag.FRAME ) { // skip the entire element
		} else {
			if ( name == Tag.HTML || name == Tag.HEAD || name == Tag.BODY || name == Tag.NOFRAMES ) {
				// skip only the start and end tags; preserve the content
				transformContents( elem );
			} else {
				super.handleElement( elem );
			}
		}
	}
/* 
 * public static void main ( String[] args )
 * throws Exception
 * {
 * HTMLTransformer out = new Concatenator( args[ args.length - 1 ] );
 * for ( int i = 0; i < args.length - 1; ++i ) {
 * Link link = new Link( args[ i ] );
 * Page page = new Page( link );
 * out.writePage( page );
 * }
 * out.close();
 * }
 */
}

