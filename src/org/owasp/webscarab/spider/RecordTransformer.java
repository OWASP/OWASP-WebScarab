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
import java.net.URL;
import org.owasp.util.StringUtil;

/** 
 * Filter for table contents (records).
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class RecordTransformer 
	extends RewritableLinkTransformer 
{
	public final static String DFLT_PROLOG =
		"<HTML><HEAD><TITLE>Extracted Records</TITLE></HEAD><BODY><TABLE>\n";
	public final static String DFLT_EPILOG = "</TABLE></BODY></HTML>\n";
	public final static String DFLT_RECORD_START = "<TR>\n<TD><A HREF=\"%u\">%n.</A>\n";
	public final static String DFLT_RECORD_END = "\n";
	public final static String DFLT_RECORD_DIVIDER = "";
	public final static String DFLT_FIELD_START = "  <TD>";
	public final static String DFLT_FIELD_END = "\n";
	public final static String DFLT_FIELD_DIVIDER = "";
	protected String _prolog;
	protected String _epilog;
	protected String _recordStart;
	protected String _recordEnd;
	protected String _recordDivider;
	protected String _fieldStart;
	protected String _fieldEnd;
	protected String _fieldDivider;
	protected int _nRecords;
	
	public RecordTransformer ( String filename )
		throws IOException
	{
		super( filename );
		_prolog = DFLT_PROLOG;
	 	_epilog = DFLT_EPILOG;
		_recordStart = DFLT_RECORD_START;
		_recordEnd = DFLT_RECORD_END;
		_recordDivider = DFLT_RECORD_DIVIDER;
		_fieldStart = DFLT_FIELD_START;
		_fieldEnd = DFLT_FIELD_END;
		_fieldDivider = DFLT_FIELD_DIVIDER;
		_nRecords = 0;
	}

	public synchronized void setProlog ( String prolog ) {
		_prolog = prolog;
	}

	public synchronized String getProlog () {
		return _prolog;
	}

	public synchronized void setEpilog ( String epilog ) {
		_epilog = epilog;
	}

	public synchronized String getEpilog () {
		return _epilog;
	}

	public synchronized void setRecordStart ( String recordStart ) {
		_recordStart = recordStart;
	}

	public synchronized String getRecordStart () {
		return _recordStart;
	}

	public synchronized void setRecordEnd ( String recordEnd ) {
		_recordEnd = recordEnd;
	}

	public synchronized String getRecordEnd () {
		return _recordEnd;
	}

	public synchronized void setRecordDivider ( String recordDivider ) {
		_recordDivider = recordDivider;
	}

	public synchronized String getRecordDivider () {
		return _recordDivider;
	}

	public synchronized void setFieldStart ( String fieldStart ) {
		_fieldStart = fieldStart;
	}

	public synchronized String getFieldStart () {
		return _fieldStart;
	}

	public synchronized void setFieldEnd ( String fieldEnd ) {
		_fieldEnd = fieldEnd;
	}

	public synchronized String getFieldEnd () {
		return _fieldEnd;
	}

	public synchronized void setFieldDivider ( String fieldDivider ) {
		_fieldDivider = fieldDivider;
	}

	public synchronized String getFieldDivider () {
		return _fieldDivider;
	}

	/** Flush the record page to disk.  Temporarily writes the epilog. */
	public synchronized void flush ()
		throws IOException
	{
		long p = getFilePointer();
		if ( 0 == _nRecords )
			emit( _prolog );
		emit( _epilog );
		seek( p );
		super.flush();
	}

	public synchronized int getRecordCount () {
		return _nRecords;
	}

	public synchronized void writeRecord ( Object[] fields, boolean asText )
		throws IOException
	{
		++_nRecords;
		emit( ( 1 == _nRecords) ? _prolog : _recordDivider );
		URL url = urlOfFirstRegion( fields );
		emitTemplate( _recordStart, url, _nRecords );
		for ( int i = 0; i < fields.length; ++i ) {
			if ( i > 0 )
				emit( _fieldDivider );
			emit( _fieldStart );
			Object f = fields[ i ];
			if ( f instanceof Region ) {
				Region r = (Region) fields[ i ];
				if ( asText )
					write( r.toText() );
				else
					write( r );
			} else {
				write( f.toString() );
			}
			emit( _fieldEnd );
		}
		emitTemplate( _recordEnd, url, _nRecords );
	}

	private URL urlOfFirstRegion ( Object[] fields ) {
		for ( int i = 0; i < fields.length; ++i ) 
			if ( fields[ i ] instanceof Region ) {
				Region r = (Region) fields[ i ];
				return r.getSource().getURL();
			}
		return null;
	}

	private void emitTemplate ( String tpl, URL url, int record )
		throws IOException
	{
		if ( tpl == null || tpl.length() == 0 )
			return ;
		tpl = StringUtil.replace( tpl, "%n", String.valueOf( record ) );
		tpl = StringUtil.replace( tpl, "%u", url != null ? url.toString() : "" );
		emit( tpl );
	}
/* 
 * Testing
 * 
 * public static void main (String[] args) throws Exception {
 * Pattern p = new TagExp (args[0].replace ('_', ' ') );
 * RecordTransformer records = new RecordTransformer (args[1]);
 * for (int i=2; i<args.length; ++i) {
 * Page page = new Page (new Link (args[i]));
 * PatternMatcher m = p.match (page);
 * for (Region r = m.nextMatch(); r != null; r = m.nextMatch())
 * records.writeRecord (r.getFields (Pattern.groups), false);
 * }
 * records.close ();
 * }
 */
}

