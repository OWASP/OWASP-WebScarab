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

import java.io.InputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import java.util.Stack;
import java.net.URL;
import java.net.MalformedURLException;

/** 
 * HTML parser.  Parses an input stream or String and
 * converts it to a sequence of Tags and a tree of Elements.
 * HTMLParser is used by Page to parse pages.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
// FIXME: make HTMLParser into an interface, and
// split this implementation into Tokenizer and TreeBuilder
public class HTMLParser {
	public static final int DFLT_BUFFER_SIZE = 10240;
	public static final int DFLT_MAX_BYTES = Integer.MAX_VALUE;
	// state takes on one of the following values:
	private static final int START = 0;
	private static final int INWORD = 1;
	private static final int ENTITY = 2;
	private static final int LT = 4;
	private static final int BANG = 5;
	private static final int BANG_DASH = 6;
	private static final int CMT = 7;
	private static final int CMT_DASH = 8;
	private static final int CMT_DASHDASH = 9;
	private static final int DIRECTIVE = 10;
	private static final int STAG = 11;
	private static final int ETAG = 12;
	private static final int ATTR = 13;
	private static final int ATTRNAME = 14;
	private static final int EQ = 15;
	private static final int AFTEREQ = 16;
	private static final int ATTRVAL = 17;
	private static final int ATTRVAL_SQ = 18;
	private static final int ATTRVAL_DQ = 19;
	private static final int DONE = 20;
	private static final int ENTNUM = 21;
	private static final int ENTREF = 22;
	
	public final int _maxBytes;
	public final int _bufferSize;
	// HTML tokenizer state machine
	private char[] _buf;
	private StringBuffer _contentBuf;
	private StringBuffer _wordBuf;
	private StringBuffer _tagName;
	private StringBuffer _attrName;
	private StringBuffer _attrVal;
	private Vector _attrs;
	private StringBuffer _entity;
	
	/** Make an HTMLParser. */
	public HTMLParser () {
		this( DFLT_MAX_BYTES, DFLT_BUFFER_SIZE );
	}
	
	/** 
	 * Make an HTMLParser which retrieves pages
	 * using the specified buffer and maximum size.
	 * @param maxBytes maximal number of bytes to be downloaded
	 * @param bufferSize size of the used buffer
	 */
	public HTMLParser ( int maxBytes, int bufferSize ) {
		_maxBytes = maxBytes;
		_bufferSize = bufferSize;
		_buf = new char[ _bufferSize ];
		_contentBuf = new StringBuffer();
		_wordBuf = new StringBuffer();
		_tagName = new StringBuffer();
		_attrName = new StringBuffer();
		_attrVal = new StringBuffer();
		_attrs = new Vector();
		_entity = new StringBuffer();
	}
	
	/** 
	 * Make an HTMLParser which retrieves pages
	 * using the specified download parameters.  Pages
	 * larger than dp.getMaxPageSize() are rejected by parse()
	 * with an IOException.
	 * @param dp download parameters used during parsing
	 */
	public HTMLParser ( DownloadParameters dp ) {
		this( dp.getMaxPageSize() * 1024, DFLT_BUFFER_SIZE );
	}

	/** 
	 * Parse an input stream.
	 * @param page Page to receive parsed HTML
	 * @param input stream containing HTML
	 */
	public void parse ( Page page, InputStream stream )
		throws IOException
	{
		Reader r = new InputStreamReader( stream );
		tokenize( page, r, true );
		buildParseTree( page );
	}

	/** 
	 * Parse an input stream.
	 * @param page Page to receive parsed HTML
	 * @param input stream containing HTML
	 */
	public void parse ( Page page, Reader stream )
		throws IOException
	{
		tokenize( page, stream, true );
		buildParseTree( page );
	}

	/** 
	 * Parse a string.
	 * @param page Page to receive parsed HTML
	 * @param content String containing HTML
	 */
	public void parse ( Page page, String content )
		throws IOException
	{
		Reader r = new StringReader( content );
		tokenize( page, r, false );
		r.close();
		buildParseTree( page );
	}

	/** 
	 * Download an input stream without parsing it.
	 * @param page Page to receive the downloaded content
	 * @param input stream containing content
	 */
	public void dontParse ( Page page, InputStream stream )
		throws IOException
	{
		Reader r = new InputStreamReader( stream );
		dontParse( page, r );
	}

	/** 
	 * Download an input stream without parsing it.
	 * @param page Page to receive the downloaded content
	 * @param r stream containing content
	 */
	public void dontParse ( Page page, Reader stream )
		throws IOException
	{
		int n;
		int total = 0;
		_contentBuf.setLength( 0 );
		while ( (n = stream.read( _buf )) != -1 ) {
			total += n;
			if ( total > _maxBytes ) {
				throw new IOException( "Page greater than " + _maxBytes + " bytes" );
			}
			_contentBuf.append( _buf, 0, n );
		}
		page._content = _contentBuf.toString();
		page._start = 0;
		page._end = _contentBuf.length();
	}

	// FIX: should entities in attr names or values be expanded?
	private void tokenize ( Page page, Reader stream, boolean saveContent )
		throws IOException
	{
		int state = START;
		int bufptr = 0;
		int buflen = 0;
		int bufbase = 0;
		// token list
		Vector tokens = new Vector();
		int wordStart = 0;
		int nWords = 0;
		Tag tag = null;
		int tagStart = 0;
		int entnum = 0;
		StringBuffer _entityTargetBuf = null;
		int postEntityState = 0;
		_contentBuf.setLength( 0 );
		while ( true ) {
			if ( bufptr >= buflen ) {
				bufptr = 0;
				bufbase += buflen;
				buflen = stream.read( _buf );
				if ( buflen == -1 )
					break;
				if ( bufbase + buflen > _maxBytes ) {
					throw new IOException( "Page exceeded " + _maxBytes + " bytes" );
				}
				if ( saveContent )
					_contentBuf.append( _buf, 0, buflen );
			}
			char c = (char) _buf[ bufptr ];
			//System.err.println ("%% state == " + state + ", ptr == " + (bufbase+bufptr) + ", c == " + c);
			switch ( state ) {
				case START:
					// after whitespace or tag
					switch ( c ) {
						case '<':
							++bufptr;
							state = LT;
							break;
						case ' ':
						case '\t':
						case '\n':
						case '\r':
							++bufptr;
							break;
						default:
							_wordBuf.setLength( 0 );
							wordStart = bufbase + bufptr;
							state = INWORD;
							break;
					}
					break;
				case INWORD:
					// Character data
					switch ( c ) {
						case '<':
							tokens.addElement( new Text( page, wordStart, bufbase + bufptr, _wordBuf.toString() ) );
							++nWords;
							state = START;
							break;
						case ' ':
						case '\t':
						case '\n':
						case '\r':
							tokens.addElement( new Text( page, wordStart, bufbase + bufptr, _wordBuf.toString() ) );
							++nWords;
							state = START;
							++bufptr;
							break;
						case '&':
							++bufptr;
							postEntityState = INWORD;
							_entityTargetBuf = _wordBuf;
							state = ENTITY;
							break;
						default:
							_wordBuf.append( (char) c );
							++bufptr;
							// state == INWORD;
							break;
					}
					break;
				//  Entities
				case ENTITY:
					if ( c == '#' ) {
						++bufptr;
						entnum = 0;
						state = ENTNUM;
					} else {
						if ( (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ) {
							_entity.setLength( 0 );
							state = ENTREF;
						} else {
							_entityTargetBuf.append( '&' );
							state = postEntityState;
						}
					}
					break;
				case ENTREF:
					if ( !Character.isLetterOrDigit( c ) ) {
						Character ent = lookupEntityRef( _entity.toString() );
						if ( ent != null ) {
							_entityTargetBuf.append( ent.charValue() );
							if ( c == ';' )
								++bufptr;
						} else {
							// unrecognized _entity -- leave
							// as-is
							_entityTargetBuf.append( '&' );
							_entityTargetBuf.append( _entity.toString() );
						}
						state = postEntityState;
					} else {
						++bufptr;
						_entity.append( c );
					// state == ENTREF;
					}
					break;
				case ENTNUM:
					if ( c == ';' || !Character.isDigit( c ) ) {
						_entityTargetBuf.append( (char) entnum );
						if ( c == ';' )
							++bufptr;
						state = postEntityState;
					} else {
						entnum = 10 * entnum + (c - '0');
						++bufptr;
					}
					break;
				case LT:
					tagStart = bufbase + bufptr - 1;
					switch ( c ) {
						case '/':
							++bufptr;
							_tagName.setLength( 0 );
							state = ETAG;
							break;
						case '!':
							++bufptr;
							state = BANG;
							break;
						default:
							if ( Character.isLetter( c ) ) {
								_tagName.setLength( 0 );
								state = STAG;
							} else {
								_wordBuf.append( '<' );
								state = INWORD;
							}
							break;
					}
					break;
				// Comments and directives.
				// Implements the (broken, but easy) Netscape rule:
				// <!-- starts a comment, --> closes.
				// All other directives <!foo> are also returned as comments.
				case BANG:
					if ( c == '-' ) {
						++bufptr;
						state = BANG_DASH;
					} else {
						state = DIRECTIVE;
					}
					break;
				case BANG_DASH:
					if ( c == '-' ) {
						++bufptr;
						state = CMT;
					} else {
						state = DIRECTIVE;
					}
					break;
				case CMT:
					if ( c == '-' ) {
						++bufptr;
						state = CMT_DASH;
					} else {
						++bufptr;
					}
					break;
				case CMT_DASH:
					if ( c == '-' ) {
						++bufptr;
						state = CMT_DASHDASH;
					} else {
						++bufptr;
						state = CMT;
					}
					break;
				case CMT_DASHDASH:
					if ( c == '>' ) {
						++bufptr;
						tag = new Tag( page, tagStart, bufbase + bufptr, Tag.COMMENT, true );
						tokens.addElement( tag );
						state = START;
					} else {
						if ( c == '-' ) {
							++bufptr;
							state = CMT_DASHDASH;
						} else {
							++bufptr;
							state = CMT;
						}
					}
					break;
				case DIRECTIVE:
					if ( c == '>' ) {
						++bufptr;
						tag = new Tag( page, tagStart, bufbase + bufptr, Tag.COMMENT, true );
						tokens.addElement( tag );
						state = START;
					} else {
						++bufptr;
					}
					break;
				// Tags
				case STAG:
					if ( c == '>' || isWhitespace( c ) ) {
						tag = new Tag( page, tagStart, bufbase + bufptr,  // tag doesn't really end here
						// -- we'll fix it up when we actually see it
						_tagName.toString(), true );
						tokens.addElement( tag );
						_attrs.setSize( 0 );
						state = ATTR;
					} else {
						_tagName.append( c );
						++bufptr;
					// state == STAG;
					}
					break;
				case ETAG:
					if ( c == '>' ) {
						++bufptr;
						tag = new Tag( page, tagStart, bufbase + bufptr, _tagName.toString(), false );
						tokens.addElement( tag );
						state = START;
					} else {
						_tagName.append( c );
						++bufptr;
					// state == ETAG
					}
					break;
				// Attributes
				case ATTR:
					if ( isWhitespace( c ) )
						++bufptr;
					else 
					if ( c == '>' ) {
						++bufptr;
						tag._end = bufbase + bufptr;
						if ( _attrs.size() > 0 ) {
							tag._htmlAttributes = new String[_attrs.size()];
							_attrs.copyInto( tag._htmlAttributes );
						}
						state = START;
					} else {
						_attrName.setLength( 0 );
						state = ATTRNAME;
					}
					break;
				case ATTRNAME:
					if ( c == '>' || c == '=' || isWhitespace( c ) ) {
						state = EQ;
					} else {
						_attrName.append( c );
						++bufptr;
					// state == ATTRNAME;
					}
					break;
				case EQ:
					if ( isWhitespace( c ) )
						++bufptr;
					else 
					if ( c == '=' ) {
						++bufptr;
						state = AFTEREQ;
					} else {
						String name = Tag.toHTMLAttributeName( _attrName.toString() );
						tag.setLabel( name );
						_attrs.addElement( name );
						state = ATTR;
					}
					break;
				case AFTEREQ:
					if ( isWhitespace( c ) )
						++bufptr;
					else
						switch ( c ) {
							case '>':{
									String name = Tag.toHTMLAttributeName( _attrName.toString() );
									tag.setLabel( name );
									_attrs.addElement( name );
									state = ATTR;
									break;
								}
							case '\'':
								++bufptr;
								_attrVal.setLength( 0 );
								state = ATTRVAL_SQ;
								break;
							case '"':
								++bufptr;
								_attrVal.setLength( 0 );
								state = ATTRVAL_DQ;
								break;
							default:
								_attrVal.setLength( 0 );
								state = ATTRVAL;
								break;
						}
					break;
				case ATTRVAL:
					if ( c == '>' || isWhitespace( c ) ) {
						String name = Tag.toHTMLAttributeName( _attrName.toString() );
						tag.setLabel( name, _attrVal.toString() );
						_attrs.addElement( name );
						state = ATTR;
					} else {
						if ( c == '&' ) {
							++bufptr;
							postEntityState = ATTRVAL;
							_entityTargetBuf = _attrVal;
							state = ENTITY;
						} else {
							++bufptr;
							_attrVal.append( c );
						// state == ATTRVAL;
						}
					}
					break;
				case ATTRVAL_SQ:
					if ( c == '\'' ) {
						++bufptr;
						String name = Tag.toHTMLAttributeName( _attrName.toString() );
						tag.setLabel( name, _attrVal.toString() );
						_attrs.addElement( name );
						state = ATTR;
					} else {
						if ( c == '&' ) {
							++bufptr;
							postEntityState = ATTRVAL_SQ;
							_entityTargetBuf = _attrVal;
							state = ENTITY;
						} else {
							++bufptr;
							_attrVal.append( c );
						// state == ATTRVAL_SQ;
						}
					}
					break;
				case ATTRVAL_DQ:
					if ( c == '"' ) {
						++bufptr;
						String name = Tag.toHTMLAttributeName( _attrName.toString() );
						tag.setLabel( name, _attrVal.toString() );
						_attrs.addElement( name );
						state = ATTR;
					} else {
						if ( c == '&' ) {
							++bufptr;
							postEntityState = ATTRVAL_DQ;
							_entityTargetBuf = _attrVal;
							state = ENTITY;
						} else {
							++bufptr;
							_attrVal.append( c );
						// state == ATTRVAL_DQ;
						}
					}
					break;
				default:
					throw new RuntimeException( "HtmlTokenizer entered illegal state " + state );
			}
		}
		// EOF
		switch ( state ) {
			case INWORD:
				// EOF terminated some text -- save the text
				tokens.addElement( new Text( page, wordStart, bufbase + bufptr, _wordBuf.toString() ) );
				++nWords;
				break;
			default:
				// EOF in the middle of tags is illegal
				// don't try to recover
				break;
		}
		int nTotal = tokens.size();
		page.tokens = new Region[nTotal];
		tokens.copyInto( page.tokens );
		page.words = new Text[nWords];
		int textnum = 0;
		page.tags = new Tag[nTotal - nWords];
		int tagnum = 0;
		for ( int i = 0; i < nTotal; ++i ) {
			if ( page.tokens[ i ] instanceof Tag )
				page.tags[ tagnum++ ] = (Tag) page.tokens[ i ];
			else
				page.words[ textnum++ ] = (Text) page.tokens[ i ];
		}
		if ( saveContent ) {
			page._content = _contentBuf.toString();
			page._start = 0;
			page._end = _contentBuf.length();
		}
	}

	private static boolean isWhitespace ( char c ) {
		return Character.isWhitespace( c );
	}
	private static HashMap entities = new HashMap();
	
	static {
		entities.put( "quot", new Character( (char) 34 ) );
		entities.put( "amp", new Character( (char) 38 ) );
		entities.put( "lt", new Character( (char) 60 ) );
		entities.put( "gt", new Character( (char) 62 ) );
		entities.put( "nbsp", new Character( (char) 160 ) );
		entities.put( "iexcl", new Character( (char) 161 ) );
		entities.put( "cent", new Character( (char) 162 ) );
		entities.put( "pound", new Character( (char) 163 ) );
		entities.put( "curren", new Character( (char) 164 ) );
		entities.put( "yen", new Character( (char) 165 ) );
		entities.put( "brvbar", new Character( (char) 167 ) );
		entities.put( "sect", new Character( (char) 167 ) );
		entities.put( "uml", new Character( (char) 168 ) );
		entities.put( "copy", new Character( (char) 169 ) );
		entities.put( "ordf", new Character( (char) 170 ) );
		entities.put( "laquo", new Character( (char) 171 ) );
		entities.put( "not", new Character( (char) 172 ) );
		entities.put( "shy", new Character( (char) 173 ) );
		entities.put( "reg", new Character( (char) 174 ) );
		entities.put( "macr", new Character( (char) 175 ) );
		entities.put( "deg", new Character( (char) 176 ) );
		entities.put( "plusmn", new Character( (char) 177 ) );
		entities.put( "sup2", new Character( (char) 178 ) );
		entities.put( "sup3", new Character( (char) 179 ) );
		entities.put( "acute", new Character( (char) 180 ) );
		entities.put( "micro", new Character( (char) 181 ) );
		entities.put( "para", new Character( (char) 182 ) );
		entities.put( "middot", new Character( (char) 183 ) );
		entities.put( "cedil", new Character( (char) 184 ) );
		entities.put( "sup1", new Character( (char) 185 ) );
		entities.put( "ordm", new Character( (char) 186 ) );
		entities.put( "raquo", new Character( (char) 187 ) );
		entities.put( "frac14", new Character( (char) 188 ) );
		entities.put( "frac12", new Character( (char) 189 ) );
		entities.put( "frac34", new Character( (char) 190 ) );
		entities.put( "iquest", new Character( (char) 191 ) );
		entities.put( "Agrave", new Character( (char) 192 ) );
		entities.put( "Aacute", new Character( (char) 193 ) );
		entities.put( "Acirc", new Character( (char) 194 ) );
		entities.put( "Atilde", new Character( (char) 195 ) );
		entities.put( "Auml", new Character( (char) 196 ) );
		entities.put( "Aring", new Character( (char) 197 ) );
		entities.put( "AElig", new Character( (char) 198 ) );
		entities.put( "Ccedil", new Character( (char) 199 ) );
		entities.put( "Egrave", new Character( (char) 200 ) );
		entities.put( "Eacute", new Character( (char) 201 ) );
		entities.put( "Ecirc", new Character( (char) 202 ) );
		entities.put( "Euml", new Character( (char) 203 ) );
		entities.put( "Igrave", new Character( (char) 204 ) );
		entities.put( "Iacute", new Character( (char) 205 ) );
		entities.put( "Icirc", new Character( (char) 206 ) );
		entities.put( "Iuml", new Character( (char) 207 ) );
		entities.put( "ETH", new Character( (char) 208 ) );
		entities.put( "Ntilde", new Character( (char) 209 ) );
		entities.put( "Ograve", new Character( (char) 210 ) );
		entities.put( "Oacute", new Character( (char) 211 ) );
		entities.put( "Ocirc", new Character( (char) 212 ) );
		entities.put( "Otilde", new Character( (char) 213 ) );
		entities.put( "Ouml", new Character( (char) 214 ) );
		entities.put( "times", new Character( (char) 215 ) );
		entities.put( "Oslash", new Character( (char) 216 ) );
		entities.put( "Ugrave", new Character( (char) 217 ) );
		entities.put( "Uacute", new Character( (char) 218 ) );
		entities.put( "Ucirc", new Character( (char) 219 ) );
		entities.put( "Uuml", new Character( (char) 220 ) );
		entities.put( "Yacute", new Character( (char) 221 ) );
		entities.put( "THORN", new Character( (char) 222 ) );
		entities.put( "szlig", new Character( (char) 223 ) );
		entities.put( "agrave", new Character( (char) 224 ) );
		entities.put( "aacute", new Character( (char) 225 ) );
		entities.put( "acirc", new Character( (char) 226 ) );
		entities.put( "atilde", new Character( (char) 227 ) );
		entities.put( "auml", new Character( (char) 228 ) );
		entities.put( "aring", new Character( (char) 229 ) );
		entities.put( "aelig", new Character( (char) 230 ) );
		entities.put( "ccedil", new Character( (char) 231 ) );
		entities.put( "egrave", new Character( (char) 232 ) );
		entities.put( "eacute", new Character( (char) 233 ) );
		entities.put( "ecirc", new Character( (char) 234 ) );
		entities.put( "euml", new Character( (char) 235 ) );
		entities.put( "igrave", new Character( (char) 236 ) );
		entities.put( "iacute", new Character( (char) 237 ) );
		entities.put( "icirc", new Character( (char) 238 ) );
		entities.put( "iuml", new Character( (char) 239 ) );
		entities.put( "eth", new Character( (char) 240 ) );
		entities.put( "ntilde", new Character( (char) 241 ) );
		entities.put( "ograve", new Character( (char) 242 ) );
		entities.put( "oacute", new Character( (char) 243 ) );
		entities.put( "ocirc", new Character( (char) 244 ) );
		entities.put( "otilde", new Character( (char) 245 ) );
		entities.put( "ouml", new Character( (char) 246 ) );
		entities.put( "divide", new Character( (char) 247 ) );
		entities.put( "oslash", new Character( (char) 248 ) );
		entities.put( "ugrave", new Character( (char) 249 ) );
		entities.put( "uacute", new Character( (char) 250 ) );
		entities.put( "ucirc", new Character( (char) 251 ) );
		entities.put( "uuml", new Character( (char) 252 ) );
		entities.put( "yacute", new Character( (char) 253 ) );
		entities.put( "thorn", new Character( (char) 254 ) );
		entities.put( "yuml", new Character( (char) 255 ) );
	}

	private static Character lookupEntityRef ( String name ) {
		return (Character) entities.get( name );
	}
	/* 
	 * Parser (constructs a canonical tree of elements)
	 * 
	 */
	Vector vElements = new Vector();
	Vector vLinks = new Vector();
	StringBuffer text = new StringBuffer();
	// elements with no content: e.g., IMG, BR, HR.  End tags for these elements
	// are simply ignored.
	private static HashMap empty = new HashMap();
	
	static {
		empty.put( Tag.AREA, Tag.AREA );
		empty.put( Tag.BASE, Tag.BASE );
		empty.put( Tag.BASEFONT, Tag.BASEFONT );
		empty.put( Tag.BGSOUND, Tag.BGSOUND );
		empty.put( Tag.BR, Tag.BR );
		empty.put( Tag.COL, Tag.COL );
		empty.put( Tag.COLGROUP, Tag.COLGROUP );
		empty.put( Tag.COMMENT, Tag.COMMENT ); // actually <!-- ... -->
		empty.put( Tag.HR, Tag.HR );
		empty.put( Tag.IMG, Tag.IMG );
		empty.put( Tag.INPUT, Tag.INPUT );
		empty.put( Tag.ISINDEX, Tag.ISINDEX );
		empty.put( Tag.LINK, Tag.LINK );
		empty.put( Tag.META, Tag.META );
		empty.put( Tag.NEXTID, Tag.NEXTID );
		empty.put( Tag.PARAM, Tag.PARAM );
		empty.put( Tag.SPACER, Tag.SPACER );
		empty.put( Tag.WBR, Tag.WBR );
	}
	// elements that close <P> (correspond to "%block" _entity in HTML 3.2 DTD)
	static HashMap blocktag = new HashMap();
	
	static {
		blocktag.put( Tag.P, Tag.P );
		blocktag.put( Tag.UL, Tag.UL );
		blocktag.put( Tag.OL, Tag.OL );
		blocktag.put( Tag.DIR, Tag.DIR );
		blocktag.put( Tag.MENU, Tag.MENU );
		blocktag.put( Tag.PRE, Tag.PRE );
		blocktag.put( Tag.XMP, Tag.XMP );
		blocktag.put( Tag.LISTING, Tag.LISTING );
		blocktag.put( Tag.DL, Tag.DL );
		blocktag.put( Tag.DIV, Tag.DIV );
		blocktag.put( Tag.CENTER, Tag.CENTER );
		blocktag.put( Tag.BLOCKQUOTE, Tag.BLOCKQUOTE );
		blocktag.put( Tag.FORM, Tag.FORM );
		blocktag.put( Tag.ISINDEX, Tag.ISINDEX );
		blocktag.put( Tag.HR, Tag.HR );
		blocktag.put( Tag.TABLE, Tag.TABLE );
		blocktag.put( Tag.H1, Tag.H1 );
		blocktag.put( Tag.H2, Tag.H2 );
		blocktag.put( Tag.H3, Tag.H3 );
		blocktag.put( Tag.H4, Tag.H4 );
		blocktag.put( Tag.H5, Tag.H5 );
		blocktag.put( Tag.H6, Tag.H6 );
		blocktag.put( Tag.ADDRESS, Tag.ADDRESS );
	}
	// maps elements which force closure to the elements that they close, e.g.,
	// LI maps to LI, DT maps to DD,DT, and all block-level tags map to P.
	private static HashMap forcesClosed = new HashMap();
	
	static {
		HashMap dd = new HashMap();
		dd.put( Tag.DD, Tag.DD );
		dd.put( Tag.DT, Tag.DT );
		forcesClosed.put( Tag.DD, dd );
		forcesClosed.put( Tag.DT, dd.clone() );
		HashMap li = new HashMap();
		li.put( Tag.LI, Tag.LI );
		forcesClosed.put( Tag.LI, li );
		HashMap option = new HashMap();
		option.put( Tag.OPTION, Tag.OPTION );
		forcesClosed.put( Tag.OPTION, option );
		HashMap tr = new HashMap();
		tr.put( Tag.TR, Tag.TR );
		forcesClosed.put( Tag.TR, tr );
		HashMap td = new HashMap();
		td.put( Tag.TD, Tag.TD );
		td.put( Tag.TH, Tag.TH );
		forcesClosed.put( Tag.TD, td );
		forcesClosed.put( Tag.TH, td );
	}
	
	static {
		HashMap p = new HashMap();
		p.put( Tag.P, Tag.P );
		Iterator it = blocktag.keySet().iterator();
		while ( it.hasNext() ) 
			merge( forcesClosed, it.next(), p );
	}
	// merge of forcesClosed plus the tag's possible containers.  For instance,
	// LI maps to LI, OL, UL, MENU, DIR.  When a forcesClosed tag like LI is
	// encountered, the parser looks upward for the first context tag.
	// Having the tag's container element included in the search ensures that
	// LI in a nested list won't close its parent LI.
	static HashMap context = new HashMap();
	
	static {
		HashMap dl = new HashMap();
		dl.put( Tag.DL, Tag.DL );
		context.put( Tag.DD, dl );
		context.put( Tag.DT, dl );
		HashMap li = new HashMap();
		li.put( Tag.LI, Tag.LI );
		li.put( Tag.OL, Tag.OL );
		li.put( Tag.MENU, Tag.MENU );
		li.put( Tag.DIR, Tag.DIR );
		context.put( Tag.LI, li );
		HashMap option = new HashMap();
		option.put( Tag.SELECT, Tag.SELECT );
		context.put( Tag.OPTION, option );
		HashMap tr = new HashMap();
		tr.put( Tag.TABLE, Tag.TABLE );
		context.put( Tag.TR, tr );
		HashMap table = new HashMap();
		table.put( Tag.TABLE, Tag.TABLE );
		table.put( Tag.TR, Tag.TR );
		context.put( Tag.TD, table );
		context.put( Tag.TH, table );
	}
	
	static {
		Iterator it = forcesClosed.keySet().iterator();
		while ( it.hasNext() ) {
			Object tagname = it.next();
			merge( context, tagname, (HashMap) forcesClosed.get( tagname ) );
		}
	}
	// NIY: handle literal and semi-literal elements (XMP, LISTING, TEXTAREA, OPTION)
	// elements whose content should be treated as plain text
	static HashMap literal = new HashMap();
	// maps link elements to their URL attribute (e.g., A maps to HREF)
	static HashMap linktag = new HashMap();
	
	static {
		linktag.put( Tag.A, "href" );
		linktag.put( Tag.AREA, "href" );
		linktag.put( Tag.APPLET, "code" );
		linktag.put( Tag.EMBED, "src" );
		linktag.put( Tag.FRAME, "src" );
		linktag.put( Tag.FORM, "action" );
		linktag.put( Tag.IMG, "src" );
		linktag.put( Tag.LINK, "href" );
		linktag.put( Tag.SCRIPT, "src" );
	}
	// elements whose text contents are crucial to the crawler
	static HashMap savetext = new HashMap();
	
	static {
		savetext.put( Tag.A, Tag.A );
		savetext.put( Tag.TITLE, Tag.TITLE );
	}
	// elements found in <HEAD>
	static HashMap headtag = new HashMap();
	
	static {
		headtag.put( Tag.META, Tag.META );
		headtag.put( Tag.TITLE, Tag.TITLE );
		headtag.put( Tag.BASE, Tag.BASE );
		headtag.put( Tag.LINK, Tag.LINK );
		headtag.put( Tag.ISINDEX, Tag.ISINDEX );
	}

	private static void merge ( HashMap map, Object tagname, HashMap tagset ) {
		HashMap currset = (HashMap) map.get( tagname );
		if ( currset == null ) {
			map.put( tagname, tagset );
		} else {
			currset.putAll( tagset );
			map.put( tagname, currset );
		}
	}

	private void buildParseTree ( Page page ) {
		boolean keepText = false;
		elems.setSize( 0 );
		openPtr = 0;
		Region[] tokens = page.tokens;
		for ( int t = 0; t < tokens.length; ++t ) {
			Region r = tokens[ t ];
			if ( r instanceof Tag ) {
				Tag tag = (Tag) r;
				String _tagName = tag.getTagName();
				if ( tag.isStartTag() ) {
					// start tag <X>
					// check if <X> forces closure of an open element
					if ( forcesClosed.containsKey( _tagName ) ) {
						Element e = findOpenElement( (HashMap) context.get( _tagName ) );
						if ( e != null && ((HashMap) forcesClosed.get( _tagName )).containsKey( e.getTagName() )
							 )
							close( e, tag._start );
					}
					// create the element and push it on the elems stack
					Element e = makeElement( page.base, tag );
					open( e );
					if ( empty.containsKey( _tagName ) ) {
						// element has no content
						// close it off right now
						close( e, tag._end );
					} else {
						if ( savetext.containsKey( _tagName ) ) {
							text.setLength( 0 );
							keepText = true;
						}
					}
					if ( _tagName == Tag.BASE ) {
						String href = tag.getHTMLAttribute( "href" );
						if ( href != null ) {
							try {
								page.base = new URL( page.base, new String( href.toCharArray() ) ); // make copy to avoid reference to page content
								} 
							catch ( MalformedURLException ex ) {} // bad URL
							catch ( NullPointerException ex ) {} // base == null
							}
					}
				} else {
					// end tag </X>
					// find matching start tag <X>
					Element e = findOpenElement( _tagName );
					if ( e != null ) {
						close( e, tag );
						if ( savetext.containsKey( _tagName ) ) {
							if ( _tagName == Tag.TITLE )
								page.title = text.toString();
							else 
							if ( e instanceof Link )
								((Link) e).setText( text.toString() );
							keepText = false;
						}
					}
				}
			} else { // r is a text token
				if ( keepText ) {
					if ( text.length() > 0 )
						text.append( ' ' );
					text.append( r.toText() );
				}
			}
		}
		// close any remaining open elements
		closeAll( page._end );
		// link together the top-level elements
		if ( !elems.empty() ) {
			int nElems = elems.size();
			Element c = (Element) elems.elementAt( 0 );
			page.root = c;
			for ( int j = 1; j < nElems; ++j ) {
				Element d = (Element) elems.elementAt( j );
				c._sibling = d;
				c = d;
			}
		}
		page.elements = new Element[vElements.size()];
		vElements.copyInto( page.elements );
		page.links = new Link[vLinks.size()];
		vLinks.copyInto( page.links );
	}

	private Element makeElement ( URL base, Tag tag ) {
		Element e = null;
		String _tagName = tag.getTagName();
		String hrefAttr = (String) linktag.get( _tagName );
		String type;
		try {
			if ( _tagName == Tag.FORM ) {
				e = new Form( tag, null, base );
				vLinks.addElement( e );
			} else {
				if ( _tagName == Tag.INPUT && (type = tag.getHTMLAttribute( "type" )) != null && (type.equalsIgnoreCase( "submit" ) || type.equalsIgnoreCase( "image" )
					) ) {
					e = new FormButton( tag, null, currentForm );
					vLinks.addElement( e );
				} else {
					if ( hrefAttr != null && tag.hasHTMLAttribute( hrefAttr ) ) {
						e = new Link( tag, null, base );
						vLinks.addElement( e );
					}
				}
			}
		} 
		catch ( MalformedURLException f ) {} // bad URL
		catch ( NullPointerException ex ) {} // base == null
		if ( e == null )
			// just make an ordinary element
			e = new Element( tag, null );
		vElements.addElement( e );
		tag._element = e;
		return e;
	}
	// Stack management
	Stack elems = new Stack();
	// stack of Elements appearing before than the current element in
	// a preorder traversal, except that completely-visited subtrees
	// are represented by their root.
	int[] openElems = new int[20];
	int openPtr = 0;
	// stack of indices of open elements in elems
	Form currentForm;

	private void open ( Element e ) {
		if ( openPtr > 0 )
			e._parent = (Element) elems.elementAt( openElems[ openPtr - 1 ] );
		else
			e._parent = null;
		elems.push( e );
		if ( e instanceof Form )
			currentForm = (Form) e;
		if ( openPtr == openElems.length ) {
			int[] newarr = new int[openElems.length + 10];
			System.arraycopy( openElems, 0, newarr, 0, openElems.length );
			openElems = newarr;
		}
		openElems[ openPtr ] = elems.size() - 1;
		++openPtr;
	}

	private Element findOpenElement ( String tagname ) {
		for ( int i = openPtr - 1; i >= 0; --i ) {
			Element e = (Element) elems.elementAt( openElems[ i ] );
			if ( tagname == e.getTagName() )
				return e;
		}
		return null;
	}

	private Element findOpenElement ( HashMap tags ) {
		for ( int i = openPtr - 1; i >= 0; --i ) {
			Element e = (Element) elems.elementAt( openElems[ i ] );
			if ( tags.containsKey( e.getTagName() ) )
				return e;
		}
		return null;
	}

	// NIY: stack up unclosed flow tags (like <B> and <A>) and reopen them
	// when the next element is opened
	private void close ( Element elem, Tag tag ) {
		elem._endTag = tag;
		tag._element = elem;
		close( elem, tag._start );
		elem._end = tag._end;
	}

	private void close ( Element elem, int end ) {
		int v;
		Element e;
		do {
			v = openElems[ --openPtr ];
			e = (Element) elems.elementAt( v );
			e._end = end;
			if ( e instanceof Form )
				currentForm = null;
			int firstChild = v + 1;
			int nElems = elems.size();
			if ( firstChild < nElems ) {
				Element c = (Element) elems.elementAt( firstChild );
				e._child = c;
				for ( int j = firstChild + 1; j < nElems; ++j ) {
					Element d = (Element) elems.elementAt( j );
					c._sibling = d;
					c = d;
				}
				elems.setSize( firstChild );
			}
		} while ( e != elem );
	}

	private void closeAll ( int end ) {
		if ( openPtr > 0 )
			close( (Element) elems.elementAt( openElems[ 0 ] ), end );
	}

	/* 
	 * Testing interface
	 * 
	 */
	public static void main ( String[] args )
		throws Exception
	{
		if ( args.length < 1 || args.length > 2 ) {
			System.err.println( "usage: HTMLParser <URL>" );
			System.exit( -1 );
		}
		Page page;
		if ( args.length == 1 )
			page = new Page( new Link( args[ 0 ] ), new HTMLParser() );
		else
			page = new Page( new URL( args[ 0 ] ), args[ 1 ], new HTMLParser() );
		/* 
		 * long tm = System.currentTimeMillis();     //??dk
		 * HTMLParser tokenizer = new HTMLParser ();
		 * tm = System.currentTimeMillis() - tm;       //??dk
		 * System.err.println("[Parsed " + args[0] + " in " + tm + "ms]");
		 */
		System.out.println( "Tokens: ------------------------------------------" );
		Region[] tokens = page.tokens;
		for ( int i = 0; i < tokens.length; ++i ) {
			System.out.println( "[" + tokens[ i ].getStart() + "," + tokens[ i ].getEnd() + "]" + tokens[ i ]
				 );
		}
		System.out.println( "Tags: ------------------------------------------" );
		Tag[] tags = page.tags;
		for ( int i = 0; i < tags.length; ++i ) {
			Tag t = tags[ i ];
			System.out.print( (t.isStartTag() ? "start tag" : "end tag") + " " + t.getTagName() );
			Iterator _attrs = t.HTMLAttributes();
			String name,  val;
			while ( _attrs.hasNext() ) {
				name = (String) _attrs.next();
				val = t.getHTMLAttribute( name );
				System.out.print( " " + name + "=\"" + val + "\"" );
			}
			System.out.println();
			System.out.println( "    " + t );
		}
		System.out.println( "Words: ------------------------------------------" );
		Text[] words = page.words;
		for ( int i = 0; i < words.length; ++i ) {
			System.out.println( words[ i ] );
		}
		System.out.println( "Elements: ------------------------------------------" );
		printout( page.root, 0 );
		System.out.println( "Links: ------------------------------------------" );
		printout( page.getLinks(), 0 );
	}

	private static String indentation ( int indent ) {
		StringBuffer s = new StringBuffer();
		for ( int i = 0; i < indent; ++i ) 
			s.append( "    " );
		return s.toString();
	}

	private static void printout ( Element element, int indent ) {
		for ( Element e = element; e != null; e = e.getSibling() ) {
			Element c = e.getChild();
			System.out.println( indentation( indent ) + e.getStartTag() + "[" + e.getStart() + "," + e.getEnd()
				+ "]" );
			if ( c != null )
				printout( c, indent + 1 );
			if ( e.getEndTag() != null )
				System.out.println( indentation( indent ) + e.getEndTag() );
		}
	}

	private static void printout ( Link[] elements, int indent ) {
		for ( int i = 0; i < elements.length; ++i ) {
			Link e = elements[ i ];
			System.out.println( indentation( indent ) + e.toDescription() );
		}
	}
}

