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

/** 
 * Element in an HTML page.  An element runs from a start tag
 * (like &lt;ul&gt;) to its matching end tag (&lt;/ul&gt;),
 * inclusive.
 * An element may have an optional end tag (like &lt;p&gt;),
 * in which case the element runs up to (but not including)
 * the tag that implicitly closes it.  For example:
 * <PRE>&lt;p&gt;Paragraph 1&lt;p&gt;Paragraph 2</PRE>
 * contains two elements, <PRE>&lt;p&gt;Paragraph 1</PRE>
 * and <PRE>&lt;p&gt;Paragraph 2</PRE>.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Element 
	extends Region 
{
	protected Tag _startTag;
	protected Tag _endTag;
	protected Element _sibling; // next sibling
	protected Element _parent;
	protected Element _child; // first child
	
	/** 
	 * Make an Element from a start tag and end tag.  The tags
	 * must be on the same Page.
	 * @param startTag Start tag of element
	 * @param endTag End tag of element (may be null)
	 */
	public Element ( Tag startTag, Tag endTag ) {
		super( startTag._source, startTag._start, null != endTag ? endTag._end : startTag._end );
		_startTag = startTag;
		_endTag = endTag;
	}
	
	/** 
	 * Make an Element from a start tag and an end position.  Used
	 * when the end tag has been omitted (like &lt;p&gt;, frequently).
	 * @param startTag Start tag of element
	 * @param end Ending offset of element
	 */
	public Element ( Tag startTag, int end ) {
		super( startTag._source, startTag._start, end );
		_startTag = startTag;
		_endTag = null;
	}

	/** 
	 * Get tag name.
	 * @return tag name (like "p"), in lower-case, String.intern()'ed form.
	 * Thus you can compare tag names with ==, as in:
	 * <CODE>getTagName() == Tag.IMG</CODE>.
	 */
	public String getTagName () {
		return _startTag.getTagName();
	}

	/** 
	 * Get start tag.
	 * @return start tag of element
	 */
	public Tag getStartTag () {
		return _startTag;
	}

	/** 
	 * Get end tag.
	 * @return end tag of element, or null if element has no end tag.
	 */
	public Tag getEndTag () {
		return _endTag;
	}

	/** 
	 * Get element's parent.
	 * @return element that contains this element, or null if at top-level.
	 */
	public Element getParent () {
		return _parent;
	}

	/** 
	 * Get element's next sibling.
	 * @return element that follows this element, or null if at end of
	 * parent's children.
	 */
	public Element getSibling () {
		return _sibling;
	}

	/** 
	 * Get element's first child.
	 * @return first element contained by this element, or null if no children.
	 */
	public Element getChild () {
		return _child;
	}

	/** 
	 * Return next element in an inorder walk of the tree,
	 * assuming this element and its children have been visited.
	 * @return next element
	 */
	public Element getNext () {
		if ( null != _sibling )
			return _sibling;
		else 
		if ( null != _parent )
			return _parent.getNext();
		else
			return null;
	}

	/** 
	 * Test if tag has an HTML attribute.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return true if tag has the attribute, false if not
	 */
	public boolean hasHTMLAttribute ( String name ) {
		return _startTag.hasHTMLAttribute( name );
	}

	/** 
	 * Get an HTML attribute's value.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @return value of attribute if it exists, TRUE if the attribute exists but has no 
	 * value, or null if tag lacks the attribute.
	 */
	public String getHTMLAttribute ( String name ) {
		return _startTag.getHTMLAttribute( name );
	}

	/** 
	 * Get an HTML attribute's value, with a default value if it doesn't exist.
	 * @param name Name of HTML attribute (e.g. "HREF").  Doesn't have to be
	 * converted with toHTMLAttributeName().
	 * @param defaultValue default value to return if the attribute
	 * doesn't exist
	 * @return value of attribute if it exists, TRUE if the attribute exists but has no
	 * value, or defaultValue if tag lacks the attribute.
	 */
	public String getHTMLAttribute ( String name, String defaultValue ) {
		return _startTag.getHTMLAttribute( name, defaultValue );
	}

	/** 
	 * Enumerate the HTML attributes found on this tag.
	 * @return enumeration of the attribute names found on this tag.
	 */
	public Iterator HTMLAttributes () {
		return _startTag.HTMLAttributes();
	}
}

