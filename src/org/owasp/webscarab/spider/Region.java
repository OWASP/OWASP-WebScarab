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

import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.Iterator;
import org.owasp.util.ArrayIterator;
import org.owasp.util.StringUtil;
import org.owasp.util.Convert;

/** 
 * Region of an HTML page.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.2 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Region {
	protected Page _source;
	protected int _start;
	protected int _end;
	protected HashMap _names;
	
	/** 
	 * Makes a Region.
	 * @param page Page containing region
	 * @param start Starting offset of region in page content
	 * @param end  Ending offset of region in page
	 */
	public Region ( Page page, int start, int end ) {
		_source = page;
		_start = start;
		_end = end;
	}
	
	/** 
	 * Makes a Region by copying another region's parameters.
	 * @param region Region to copy
	 */
	public Region ( Region region ) {
		_source = region._source;
		_start = region._start;
		_end = region._end;
		if ( null != region._names )
			_names = (HashMap) region._names.clone();
	}

	/** 
	 * Gets page containing the region.
	 * @return page containing the region
	 */
	public Page getSource () {
		return _source;
	}

	/** 
	 * Gets starting offset of region in page content.
	 * @return zero-based offset where region begins in page content
	 */
	public int getStart () {
		return _start;
	}

	/** 
	 * Gets offset after end of region.
	 * @return zero-based offset just after the end of the region.
	 */
	public int getEnd () {
		return _end;
	}

	/** 
	 * Gets length of the region.  Equivalent to getEnd() - getStart().
	 * @return length of the HTML region in bytes.
	 */
	public int getLength () {
		return _end - _start;
	}

	/** 
	 * Converts the region to HTML, e.g. "&lt;tag&gt;&lt;tag&gt;&lt;tag&gt;text text&lt;/tag&gt;"
	 * If the region does not contain HTML, then this function quotes all the <, >, &
	 * characters found in the page content, and wraps the result
	 * in <PRE> and </PRE>.
	 * @return a string consisting of the HTML content contained by this region.
	 */
	public String toHTML () {
		return _source.substringHTML( _start, _end );
	}

	/** 
	 * Converts the region to tagless text, e.g. "text text".
	 * @return a string consisting of the text in the page contained by this region
	 */
	public String toText () {
		return _source.substringText( _start, _end );
	}

	/** 
	 * Converts the region to HTML tags with no text, e.g. "&lt;tag&gt;&lt;tag&gt;&lt;/tag&gt;".
	 * @return a string consisting of the tags in the page contained by this region
	 */
	public String toTags () {
		return _source.substringText( _start, _end );
	}

	/** 
	 * Gets region as raw content.
	 * @return string representation of the region
	 */
	public String toString () {
		return _source.substringContent( _start, _end );
	}

	/** 
	 * Get the root HTML element of the region.
	 * @return first HTML element whose start tag is
	 * completely in the region.
	 */
	public Element getRootElement () {
		Element[] elements = _source.getElements();
		if ( elements == null )
			return null;
		int k = Region.findStart( elements, _start );
		if ( k == elements.length )
			return null;
		Element root = elements[ k ];
		Tag startTag = root.getStartTag();
		if ( startTag.getEnd() > _end )
			return null;
		return root;
	}

	/** 
	 * Finds a region that starts at or after a given position.
	 * @param regions array of regions sorted by starting offset
	 * @param p Desired starting offset
	 * @return index <i>k</i> into regions such that:
	 * <OL><LI>forall j&lt;k: regions[j].start &lt; p
	 * <LI>regions[k].start &gt;= p
	 * </OL>
	 */
	public static int findStart ( Region[] regions, int p ) {
		// returns k such that forall j<k : regions[j].start < p
		//                     && regions[k].start >= p
		int lo = 0;
		int hi = regions.length;
		// invariant: forall j<lo : regions[j].start < p
		//         && forall j>=hi : regions[j].start >= p
		while ( lo != hi ) {
			int mid = (hi + lo) / 2;
			if ( regions[ mid ]._start < p )
				lo = mid + 1;
			else
				hi = mid;
		}
		return hi;
	}

	/** 
	 * Finds a region that ends at or after a given position.
	 * @param regions array of regions sorted by ending offset
	 * @param p Desired ending offset
	 * @return index <i>k</i> into regions such that:
	 * <OL><LI>forall j&lt;k: regions[j].end &lt; p
	 * <LI>regions[k].end &gt;= p
	 * </OL>
	 */
	public static int findEnd ( Region[] regions, int p ) {
		// returns k such that forall j<k : regions[j].end < p
		//                     && regions[k].end >= p
		int lo = 0;
		int hi = regions.length;
		// invariant: forall j<lo : regions[j].end < p
		//         && forall j>=hi : regions[j].end >= p
		while ( lo != hi ) {
			int mid = (hi + lo) / 2;
			if ( regions[ mid ]._end < p )
				lo = mid + 1;
			else
				hi = mid;
		}
		return hi;
	}

	/** 
	 * Makes a new Region containing two regions.
	 * @param r end of spanning region
	 * @return region from the beginning of this region to the end of r.  Both regions must have
	 * the same source, and r must end after this region starts.
	 */
	public Region span ( Region r ) {
		return new Region( _source, _start, r._end );
	}
	protected HashMap names = null;
	static final int INITIAL_SIZE = 4;
	// typically only a handful of names are set
	/** 
	 * Default value for labels set with setLabel (name).  Value of TRUE is
	 * "true".
	 */
	public static final String TRUE = "true".intern();

	/** 
	 * Set an object-valued label.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @param value value set for label.  If null, the label is removed.
	 */
	public void setObjectLabel ( String name, Object value ) {
		if ( value == null ) {
			removeLabel( name );
		} else {
			if ( null == _names )
				_names = new HashMap( INITIAL_SIZE );
			_names.put( name, value );
		}
	}

	/** 
	 * Get an object-valued label.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @return Object value set for label, or null if label not set
	 */
	public Object getObjectLabel ( String name ) {
		return null != _names ? _names.get( name ) : null;
	}

	/** 
	 * Enumerate the labels of the region.
	 * @return iteration producing label names
	 */
	public Iterator iterateObjectLabels () {
		return _names != null ? _names.keySet().iterator() : new ArrayIterator( null );
	}

	/** 
	 * Get a String containing the labels of the region.
	 * @return string containing the label names, separated by spaces
	 */
	public String getObjectLabels () {
		Iterator it = iterateObjectLabels();
		StringBuffer buf = new StringBuffer();
		while ( it.hasNext() ) {
			if ( buf.length() > 0 )
				buf.append( ' ' );
			buf.append( (String) it.next() );
		}
		return buf.toString();
	}

	/** 
	 * Set a string-valued label.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @param value value set for label.  If null, the label is removed.
	 */
	public void setLabel ( String name, String value ) {
		setObjectLabel( name, value );
	}

	/** 
	 * Set a label on the region.  The value of the label defaults to TRUE.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 */
	public void setLabel ( String name ) {
		setObjectLabel( name, TRUE );
	}

	/** 
	 * Get a label's value.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @return value of label, or null if label not set
	 */
	public String getLabel ( String name ) {
		Object obj = getObjectLabel( name );
		if ( obj == null )
			return null;
		else 
		if ( obj instanceof Region[] )
			return null; // NIY
			 else 
		if ( obj instanceof Region )
			return ((Region) obj).toText();
		else
			return obj.toString();
	}

	/** 
	 * Get a label's value.  If the label is not set, return defaultValue.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @param defaultValue default value that should be returned if label is not set
	 * @return value of label, or defaultValue if not set
	 */
	public String getLabel ( String name, String defaultValue ) {
		String val = getLabel( name );
		return (val != null) ? val : defaultValue;
	}

	/** 
	 * Get a label's value as a number.  Returns the first number (integral or floating point) that can be
	 * parsed from the label's value, skipping an arbitrary amount of junk.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @param defaultValue default value that should be returned if label is not set
	 * @return numeric value of label, or defaultValue if not set or no number is found
	 */
	public Number getNumericLabel ( String name, Number defaultValue ) {
		String val = getLabel( name );
		if ( val == null )
			return defaultValue;
		try {
			return Convert.toNumber( val );
		} 
		catch ( NumberFormatException e ) {
			return defaultValue;
		}
	}

	/** 
	 * Test if a label is set.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 * @return true if label is set, otherwise false
	 */
	public boolean hasLabel ( String name ) {
		return _names != null && _names.containsKey( name );
	}

	/** 
	 * Test if one or more of several labels are set.
	 * @param expr a list of label names separated by spaces
	 * @return true if region has at least one of the labels in expr
	 */
	public boolean hasAnyLabels ( String expr ) {
		StringTokenizer tok = new StringTokenizer( expr );
		while ( tok.hasMoreElements() ) 
			if ( hasLabel( tok.nextToken() ) )
				return true;
		return false;
	}

	/** 
	 * Test if one or more of several labels are set.
	 * @param labels an array of label names
	 * @return true if region has at least one of the labels
	 */
	public boolean hasAnyLabels ( String[] labels ) {
		for ( int i = 0; i < labels.length; ++i ) 
			if ( hasLabel( labels[ i ] ) )
				return true;
		return false;
	}

	/** 
	 * Test if all of several labels are set.
	 * @param expr a list of label names separated by spaces
	 * @return true if region has at least one of the labels in expr
	 */
	public boolean hasAllLabels ( String expr ) {
		StringTokenizer tok = new StringTokenizer( expr );
		while ( tok.hasMoreElements() ) 
			if ( !hasLabel( tok.nextToken() ) )
				return false;
		return true;
	}

	/** 
	 * Test if all of several labels are set.
	 * @param labels an array of label names
	 * @return true if region has all of the labels
	 */
	public boolean hasAllLabels ( String[] labels ) {
		for ( int i = 0; i < labels.length; ++i ) 
			if ( !hasLabel( labels[ i ] ) )
				return false;
		return true;
	}

	/** 
	 * Remove a label.
	 * @param name name of label (case-sensitive, whitespace permitted)
	 */
	public void removeLabel ( String name ) {
		if ( _names != null )
			_names.remove( name );
	}

	/** 
	 * Name a subregion (by setting a label to point to it).
	 * @param name label name (case-sensitive, whitespace permitted)
	 * @param region subregion to name
	 */
	public void setField ( String name, Region region ) {
		setObjectLabel( name, region );
	}

	/** 
	 * Get a named subregion.
	 * @param name label name (case-sensitive, whitespace permitted)
	 * @return the named region, or null if label not set to a region
	 */
	public Region getField ( String name ) {
		try {
			return (Region) getObjectLabel( name );
		} 
		catch ( ClassCastException e ) {
			return null;
		}
	}

	/** 
	 * Name a set of subregions (by pointing a label to them).
	 * @param name label name (case-sensitive, whitespace permitted)
	 * @param regions list of subregions
	 */
	public void setFields ( String name, Region[] regions ) {
		setObjectLabel( name, regions );
	}

	/** 
	 * Get a set of named subregions.  Note that subregions named with
	 * setField() cannot be retrieved with getFields(); use getField() instead.
	 * @param name label name (case-sensitive, whitespace permitted)
	 * @return the named subregions, or null if label not set to a set
	 * of subregions
	 */
	public Region[] getFields ( String name ) {
		try {
			return (Region[]) getObjectLabel( name );
		} 
		catch ( ClassCastException e ) {
			return null;
		}
	}
}

