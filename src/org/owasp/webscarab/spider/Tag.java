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

import java.util.Iterator;
import org.owasp.util.ArrayIterator;

/** 
 * Tag in an HTML page.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.2 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Tag 
	extends Region 
{
	String _tagName;
	boolean _startTag;
	String[] _htmlAttributes; // HTML attributes on this tag (lower case and interned)
	Element _element;
	
	/** 
	 * Make a Tag.
	 * @param page Page containing tag
	 * @param start Starting offset of tag in page
	 * @param end Ending offset of tag
	 * @param tagName Name of tag (like "p")
	 * @param startTag true for start tags (like "&lt;p&gt;"), false for end tags ("&lt;/p&gt;")
	 */
	public Tag ( Page page, int start, int end, String tagName, boolean startTag ) {
		super( page, start, end );
		_tagName = tagName.toLowerCase().intern();
		_startTag = startTag;
		_htmlAttributes = null;
	}

	/** 
	 * Get tag name.
	 * @return tag name (like "p"), in lower-case, String.intern()'ed form.
	 */
	public String getTagName () {
		return _tagName;
	}

	/** 
	 * Get element to which this tag is the start or end tag.
	 * @return element, or null if tag has no element.
	 */
	public Element getElement () {
		return _element;
	}

	/** 
	 * Convert a String to a tag name.  Tag names are lower-case, intern()'ed
	 * Strings.  Thus you can compare tag names with ==, as in:
	 * <CODE>getTagName() == Tag.IMG</CODE>.
	 * @param name Name to convert (e.g., "P")
	 * @return tag name (e.g. "p"), in lower-case, String.intern()'ed form.
	 */
	public static String toTagName ( String name ) {
		return name.toLowerCase().intern();
	}

	/** 
	 * Test if tag is a start tag.  Equivalent to !isEndTag().
	 * @return true if and only if tag is a start tag (like "&lt;P&gt;")
	 */
	public boolean isStartTag () {
		return _startTag;
	}

	/** 
	 * Test if tag is an end tag.  Equivalent to !isStartTag().
	 * @return true if and only if tag is a start tag (like "&lt;/P&gt;")
	 */
	public boolean isEndTag () {
		return !_startTag;
	}

	/** 
	 * Test if tag is a block-level tag.  Equivalent to !isFlowTag().
	 * @return true if and only if tag is a block-level tag (like "&lt;P&gt;")
	 */
	public boolean isBlockTag () {
		return HTMLParser.blocktag.containsKey( _tagName );
	}

	/** 
	 * Test if tag is a flow-level tag.  Equivalent to !isBlockTag().
	 * @return true if and only if tag is a flow-level tag (like "&lt;A&gt;")
	 */
	public boolean isFlowTag () {
		return !isBlockTag();
	}

	/** 
	 * Test if tag belongs in the <HEAD> element.
	 * @return true if and only if tag is a HEAD-level tag (like "&lt;TITLE&gt;")
	 */
	public boolean isHeadTag () {
		return HTMLParser.headtag.containsKey( _tagName );
	}

	/** 
	 * Test if tag belongs in the <BODY> element.
	 * @return true if and only if tag is a BODY-level tag (like "&lt;A&gt;")
	 */
	public boolean isBodyTag () {
		return !isHeadTag() && _tagName != HTML && _tagName != HEAD && _tagName != BODY;
	}

	/** 
	 * Convert a String to an HTML attribute name.  Attribute names are
	 * lower-case, intern()'ed
	 * Strings.  Thus you can compare attribute names with ==.
	 * @param name Name to convert (e.g., "HREF")
	 * @return tag name (e.g. "href"), in lower-case, String.intern()'ed form.
	 */
	public static String toHTMLAttributeName ( String name ) {
		return name.toLowerCase().intern();
	}

	/** 
	 * Test if tag has an HTML attribute.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return true if tag has the attribute, false if not
	 */
	public boolean hasHTMLAttribute ( String name ) {
		if ( null == _htmlAttributes )
			return false;
		name = toHTMLAttributeName( name );
		for ( int i = 0; i < _htmlAttributes.length; ++i ) 
			if ( _htmlAttributes[ i ] == name )
				return true;
		return false;
	}

	/** 
	 * Get an HTML attribute's value.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return value of attribute if it exists, TRUE if the attribute exists but has no value, or null if tag lacks the attribute.
	 */
	public String getHTMLAttribute ( String name ) {
		if ( null == _htmlAttributes  )
			return null;
		name = toHTMLAttributeName( name );
		for ( int i = 0; i < _htmlAttributes.length; ++i ) 
			if ( _htmlAttributes[ i ] == name )
				return getLabel( name );
		return null;
	}

	/** 
	 * Get an HTML attribute's value, with a default value if it doesn't exist.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @param defaultValue default value to return if the attribute
	 * doesn't exist
	 * @return value of attribute if it exists, TRUE if the attribute exists but has no value, or defaultValue if tag lacks the attribute.
	 */
	public String getHTMLAttribute ( String name, String defaultValue ) {
		String val = getHTMLAttribute( name );
		return val != null ? val : defaultValue;
	}

	/** 
	 * Get number of HTML attributes on this tag.
	 * @return number of HTML attributes
	 */
	public int countHTMLAttributes () {
		return _htmlAttributes != null ? _htmlAttributes.length : 0;
	}

	/** 
	 * Get all the HTML attributes found on this tag.
	 * @return array of name-value pairs, alternating between
	 * names and values.  Thus array[0] is a name, array[1] is a value,
	 * array[2] is a name, etc.
	 */
	public String[] getHTMLAttributes () {
		if ( null == _htmlAttributes )
			return new String[0];
		String[] result = new String[_htmlAttributes.length * 2];
		for ( int i = 0,  j = 0; i < _htmlAttributes.length; ++i ) {
			String name = _htmlAttributes[ i ];
			result[ j++ ] = name;
			result[ j++ ] = getLabel( name );
		}
		return result;
	}

	/** 
	 * Enumerate the HTML attributes found on this tag.
	 * @return enumeration of the attribute names found on this tag.
	 */
	public Iterator HTMLAttributes () {
		return new ArrayIterator( _htmlAttributes );
	}

	/** 
	 * Copy this tag, removing an HTML attribute.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return copy of this tag with named attribute removed.  The copy is
	 * a region of a fresh page containing only the tag.
	 */
	public Tag removeHTMLAttribute ( String name ) {
		return replaceHTMLAttribute( name, null );
	}

	/** 
	 * Copy this tag, setting an HTML attribute's value to TRUE.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return copy of this tag with named attribute set to TRUE.  The copy is
	 * a region of a fresh page containing only the tag.
	 */
	public Tag replaceHTMLAttribute ( String name ) {
		return replaceHTMLAttribute( name, TRUE );
	}

	/** 
	 * Copy this tag, setting an HTML attribute's value.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @param value New value for the attribute
	 * @return copy of this tag with named attribute set to value.
	 * The copy is
	 * a region of a fresh page containing only the tag.
	 */
	public Tag replaceHTMLAttribute ( String name, String value ) {
		name = toHTMLAttributeName( name );
		// illegal!
		if ( !_startTag )
			return this;
		StringBuffer newstr = new StringBuffer();
		String[] newattrs = null;
		newstr.append( '<' );
		newstr.append( _tagName );
		boolean foundit = false;
		int len = _htmlAttributes.length;
		for ( int i = 0; i < len; ++i ) {
			String attrName = _htmlAttributes[ i ];
			String attrVal;
			// FIX: entity-encode attrVal
			if ( attrName == name ) {
				newattrs = _htmlAttributes;
				foundit = true;
				if ( value == null )
					continue;
				attrVal = value;
			} else {
				attrVal = getLabel( attrName );
			}
			newstr.append( ' ' );
			newstr.append( attrName );
			if ( attrVal != TRUE ) {
				newstr.append( '=' );
				if ( attrVal.indexOf( '"' ) == -1 ) {
					newstr.append( '"' );
					newstr.append( attrVal );
					newstr.append( '"' );
				} else {
					newstr.append( '\'' );
					newstr.append( attrVal );
					newstr.append( '\'' );
				}
			}
		}
		if ( !foundit && value != null ) {
			// add new attribute at end
			newstr.append( ' ' );
			newstr.append( name );
			if ( value != name ) {
				newstr.append( '=' );
				if ( value.indexOf( '"' ) == -1 ) {
					newstr.append( '"' );
					newstr.append( value );
					newstr.append( '"' );
				} else {
					newstr.append( '\'' );
					newstr.append( value );
					newstr.append( '\'' );
				}
			}
			// append name to list of attribute names
			newattrs = new String[len + 1];
			System.arraycopy( _htmlAttributes, 0, newattrs, 0, len );
			newattrs[ len ] = name;
		}
		newstr.append( '>' );
		Tag newTag = new Tag( new Page( newstr.toString() ), 0, newstr.length(), _tagName, _startTag );
		newTag.names = names;
		newTag._htmlAttributes = newattrs;
		newTag.setLabel( name, value );
		return newTag;
	}
	/* 
	 * Commonly useful tag names.
	 * Derived from <a href="http://www.sandia.gov/sci_compute/elements.html">HTML Elements</a>
	 * at Sandia National Labs.
	 */
	/** anchor tag <code>a</code> */
	public static final String A = "a".intern();
	/** abbreviation tag <code>abbrev</code> */
	public static final String ABBREV = "abbrev".intern();
	/** acronym tag <code>acronym</code> */
	public static final String ACRONYM = "acronym".intern();
	/** address tag <code>address</code> */
	public static final String ADDRESS = "address".intern();
	/** applet tag <code>applet</code> */
	public static final String APPLET = "applet".intern();
	/** area tag <code>area</code> */
	public static final String AREA = "area".intern();
	/** bold tag <code>b</code> */
	public static final String B = "b".intern();
	/** URL base tag <code>base</code> */
	public static final String BASE = "base".intern();
	/** base font tag <code>basefont</code> */
	public static final String BASEFONT = "basefont".intern();
	/** tag <code></code> */
	public static final String BDO = "bdo".intern();
	/** background sound tag <code></code> */
	public static final String BGSOUND = "bgsound".intern();
	/** big tag <code>big</code> */
	public static final String BIG = "big".intern();
	/** blink tag <code>blink</code> */
	public static final String BLINK = "blink".intern();
	/** blockquote tag <code>blockquote</code> */
	public static final String BLOCKQUOTE = "blockquote".intern();
	/** body tag <code>body</code> */
	public static final String BODY = "body".intern();
	/** line break tag <code>br</code> */
	public static final String BR = "br".intern();
	/** caption tag <code>caption</code> */
	public static final String CAPTION = "caption".intern();
	/** center tag <code>center</code> */
	public static final String CENTER = "center".intern();
	/** cite tag <code>cite</code> */
	public static final String CITE = "cite".intern();
	/** code tag <code>code</code> */
	public static final String CODE = "code".intern();
	/** column tag <code>col</code> */
	public static final String COL = "col".intern();
	/** column group tag <code>colgroup</code> */
	public static final String COLGROUP = "colgroup".intern();
	/** comment tag part<code>!</code> */
	public static final String COMMENT = "!".intern();
	/** tag <code></code> */
	public static final String DD = "dd".intern();
	/** tag <code></code> */
	public static final String DEL = "del".intern();
	/** tag <code></code> */
	public static final String DFN = "dfn".intern();
	/** tag <code></code> */
	public static final String DIR = "dir".intern();
	/** division tag <code>div</code> */
	public static final String DIV = "div".intern();
	/** tag <code></code> */
	public static final String DL = "dd".intern();
	/** tag <code></code> */
	public static final String DT = "dt".intern();
	/** emphasized tag <code>em</code> */
	public static final String EM = "em".intern();
	/** embed object tag <code>embed</code> */
	public static final String EMBED = "embed".intern();
	/** font tag <code>font</code> */
	public static final String FONT = "font".intern();
	/** frame tag <code>frame</code> */
	public static final String FRAME = "frame".intern();
	/** frameset tag <code>frameset</code> */
	public static final String FRAMESET = "frameset".intern();
	/** form tag <code>form</code> */
	public static final String FORM = "form".intern();
	/** headline 1 tag <code>h1</code> */
	public static final String H1 = "h1".intern();
	/** headline 2 tag <code>h2</code> */
	public static final String H2 = "h2".intern();
	/** headline 3 tag <code>h3</code> */
	public static final String H3 = "h3".intern();
	/** headline 4 tag <code>h4</code> */
	public static final String H4 = "h4".intern();
	/** headline tag <code>h5</code> */
	public static final String H5 = "h5".intern();
	/** headline tag <code>h6</code> */
	public static final String H6 = "h6".intern();
	/** page head tag <code>head</code> */
	public static final String HEAD = "head".intern();
	/** horizontal rule tag <code>hr</code> */
	public static final String HR = "hr".intern();
	/** html tag <code>html</code> */
	public static final String HTML = "html".intern();
	/** italic tag <code>i</code> */
	public static final String I = "i".intern();
	/** tag <code></code> */
	public static final String IMG = "img".intern();
	/** tag <code></code> */
	public static final String INPUT = "input".intern();
	/** tag <code></code> */
	public static final String ISINDEX = "isindex".intern();
	/** tag <code></code> */
	public static final String KBD = "kbd".intern();
	/** tag <code></code> */
	public static final String LI = "li".intern();
	/** tag <code></code> */
	public static final String LINK = "link".intern();
	/** tag <code></code> */
	public static final String LISTING = "listing".intern();
	/** tag <code></code> */
	public static final String MAP = "map".intern();
	/** tag <code></code> */
	public static final String MARQUEE = "marquee".intern();
	/** tag <code></code> */
	public static final String MENU = "menu".intern();
	/** tag <code></code> */
	public static final String META = "meta".intern();
	/** tag <code></code> */
	public static final String NEXTID = "nextid".intern();
	/** tag <code></code> */
	public static final String NOBR = "nobr".intern();
	/** tag <code></code> */
	public static final String NOEMBED = "noembed".intern();
	/** tag <code></code> */
	public static final String NOFRAMES = "noframes".intern();
	/** tag <code></code> */
	public static final String OBJECT = "object".intern();
	/** tag <code></code> */
	public static final String OL = "ol".intern();
	/** tag <code></code> */
	public static final String OPTION = "option".intern();
	/** tag <code></code> */
	public static final String P = "p".intern();
	/** tag <code></code> */
	public static final String PARAM = "param".intern();
	/** tag <code></code> */
	public static final String PLAINTEXT = "plaintext".intern();
	/** tag <code></code> */
	public static final String PRE = "pre".intern();
	/** tag <code></code> */
	public static final String SAMP = "samp".intern();
	/** tag <code></code> */
	public static final String SCRIPT = "script".intern();
	/** tag <code></code> */
	public static final String SELECT = "select".intern();
	/** tag <code></code> */
	public static final String SMALL = "small".intern();
	/** tag <code></code> */
	public static final String SPACER = "spacer".intern();
	/** tag <code></code> */
	public static final String STRIKE = "strike".intern();
	/** tag <code></code> */
	public static final String STRONG = "strong".intern();
	/** tag <code></code> */
	public static final String STYLE = "style".intern();
	/** tag <code></code> */
	public static final String SUB = "sub".intern();
	/** tag <code></code> */
	public static final String SUP = "sup".intern();
	/** tag <code></code> */
	public static final String TABLE = "table".intern();
	/** tag <code></code> */
	public static final String TD = "td".intern();
	/** tag <code></code> */
	public static final String TEXTAREA = "textarea".intern();
	/** tag <code></code> */
	public static final String TH = "th".intern();
	/** tag <code></code> */
	public static final String TITLE = "title".intern();
	/** tag <code></code> */
	public static final String TR = "tr".intern();
	/** tag <code></code> */
	public static final String TT = "tt".intern();
	/** tag <code></code> */
	public static final String U = "u".intern();
	/** tag <code></code> */
	public static final String UL = "ul".intern();
	/** tag <code></code> */
	public static final String VAR = "var".intern();
	/** tag <code></code> */
	public static final String WBR = "wbr".intern();
	/** tag <code></code> */
	public static final String XMP = "xmp".intern();
	/** Length of longest tag name (BLOCKQUOTE). */
	public static int MAX_LENGTH = 10;
}

