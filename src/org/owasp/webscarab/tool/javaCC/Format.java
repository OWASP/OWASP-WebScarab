package org.owasp.webscarab.tool.javaCC;

import java.util.ArrayList;
import java.util.Iterator;
import java.io.PrintStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.ByteArrayOutputStream;
import org.owasp.webscarab.util.StringUtil;
import org.owasp.webscarab.util.FileUtil;

/**
 * Formats java source.
 *
 * @since beta 1
 * @version beta 1<br />$Revision: 1.1 $ $Author: istr $
 * @author istr
 */
public class Format 
  implements JavaOneDotTwoVisitor, JavaOneDotTwoConstants 
{
  private static final String JDOC_START = "/**\n * <TODO description>\n";
  private static final String JDOC_END = " */";
  private static final String JDOC_CLASS_DECL = " *\n * @since <RELEASE>\n * @version <RELEASE><br />"
                                                 + "$" + "Revision" + "$ $"
                                                 + "Author"
                                                 + "$\n * @author <AUTHOR>\n";
  private static final int MAXCOL = 90;
  int _lineLength;
  int _indent;
  int _row;
  int _col;
  private boolean _nl;
  PrintStream _out;
  
  /**
   * Creates a new Formatter with a given indentation level 
   * and a given line length.
   * @param out the PrintStream used to print the formatted file
   * @param lineLength maximum line length in the output
   */
  public Format ( PrintStream out, int lineLength ) {
    _out = out;
    _lineLength = lineLength;
    _indent = 0;
    _row = 1;
    _col = 1;
    _nl = true;
  }
  
  /**
   * Creates a new Formatter with indentation level 2 and line length 80.
   * @param out the PrintStream used to print the formatted file
   */
  public Format ( PrintStream out ) {
    this( out, MAXCOL );
  }

  private void indent ( StringBuffer buf ) {
    _indent++;
    if ( ! _nl )
      return;
    _col ++;
    buf.append( "\t" );
    _nl = true;
  }

  private void outdent () {
    _indent--;
  }

  private void newline ( StringBuffer buf ) {
    flush( buf );
    _row++;
    _col = _indent;
    for ( int i = 0; i < _col; i++ ) 
      buf.append( "\t" );
    _nl = true;
  }

  private void softnewline ( StringBuffer buf ) {
    if ( _nl )
      return;
    _row++;
    _col = _indent;
    buf.append( "\n" );
    for ( int i = 0; i < _col; i++ ) 
      buf.append( "\t" );
    _nl = true;
  }

  private void lastposnewline ( StringBuffer buf ) {
    flush( buf );
    _row++;
    for ( int i = 0; i < _indent; i++ )
      buf.append( "\t" );
    _col = _indent;
    _nl = true;
  }

  private void softlastposnewline ( StringBuffer buf ) {
    buf.append( "\n" );
    for ( int i = 0; i < _indent; i++ )
      buf.append( "\t" );
    _col = _indent;
    _nl = true;
  }

	private String formatMultilineComment ( String comment, boolean formal ) {
	  comment = comment.substring( 3, comment.length() - 2 ).trim();
    String[] lines = StringUtil.split( comment, '\n' );
		int lc = lines.length;
		String start = formal ? "/** " : "/* ";
		if ( 1 == lc )
			return start + lines[ 0 ].trim() + " */";
		StringBuffer buf = new StringBuffer( start );
		StringBuffer ind = new StringBuffer();
		for ( int j = 0; j < _indent; j++ )
			ind.append( '\t' );
		buf.append( '\n' );	
		for ( int i = 0; i < lines.length; i++ ) {
			buf.append( ind ).append( " * " );
			String line = lines[ i ].trim();
			if ( line.startsWith( "*" ) && 0 < line.length() )
				line = line.substring( 1 ).trim(); 
			buf.append( line ).append( '\n' );
		}
		buf.append( ind ).append( " */" );
		return buf.toString();
	}

  private void printEOLComment ( SimpleNode n, StringBuffer buf ) {
    if ( null == n )
      return ;
    Token tt = n.getToken();
    Token t = null == tt
              ? null
              : tt.next;
    if ( null != t ) {
      Token lastT = t;
      Token spT = t.specialToken;
      if ( null != spT ) {
        while ( null != spT.specialToken ) {
          lastT = spT;
          spT = spT.specialToken;
        }
        if ( spT.image.startsWith( "//" ) ) {
          if ( spT.beginLine == tt.endLine ) {
            softspace( buf );
            out( buf, spT.image.trim() );
						softnewline( buf );
            lastT.specialToken = null; 
          }
        }
      }
    }
  }

  private void printSpecialTokens ( SimpleNode n, StringBuffer buf ) {
    Token t = n.getToken();
		if ( null == t )
			return;
    ArrayList l = new ArrayList();
    while ( null != t ) {
      t = t.specialToken; // recurse upwards
      l.add( 0, t );
    }
    Iterator it = l.iterator();
    it.next();
    boolean hasSpecialTokens = false;
    while ( it.hasNext() ) {
      hasSpecialTokens = true;
      t = (Token) it.next();
			if ( FORMAL_COMMENT == t.kind || MULTI_LINE_COMMENT == t.kind )
	      out( buf, formatMultilineComment( t.image.trim(), FORMAL_COMMENT == t.kind ) );
			else
	      out( buf, t.image.trim() );
      softnewline( buf );
    }
  }

  public void print ( SimpleNode n ) {
    StringBuffer buf = new StringBuffer();
    _row = 1;
    _col = 1;
    n.jjtAccept( this, buf );
    flush( buf );
  }

  private void flush ( StringBuffer buf ) {
    _out.println( buf );
    buf.delete( 0, buf.length() );
  }

  private void out ( StringBuffer buf, String what ) {
    _nl = false;
    buf.append( what );
    _col += what.length();
  }

/*  private void multiout ( StringBuffer buf, String what ) {
    _nl = false;
    String[] lines = StringUtil.split( what, "\n" );
    int length = lines[ 0 ].length();
    if ( 1 == lines.length ) {
      buf.append( lines[ 0 ] );
      _col += length;
      return ;
    }
    int pos = buf.toString().lastIndexOf( '\n' ) - _indent;
    pos = 0 > pos
          ? buf.length()
          : buf.length() - pos;
    buf.append( lines[ 0 ] );
    for ( int i = 1; i < lines.length; i++ ) {
      buf.append( '\n' );
      for ( int j = 0; j < _indent; j++ )
        buf.append( '\t' );
      for ( int j = 0; j < pos - _indent - 1; j++ ) 
        buf.append( " " );
      buf.append( lines[ i ].trim() );
      int nl = lines[ i ].trim().length();
      if ( nl > length )
        length = nl;
      
    }
    _col += length;
  } */

  private void softspace ( StringBuffer buf ) {
    if ( _indent >= _col )
      return;
    buf.append( " " );
    _col++;
  }

  /**
   * Iterates over child nodes with a softspace after each node.
   */
  private void recurseSpaced ( SimpleNode node, StringBuffer buf, int start, 
                               int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 < cnt && start <= end && end <= cnt ) {
      for ( int i = start; i < end; i++ ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i );
        if ( null != c ) {
          c.jjtAccept( this, buf );
          softspace( (StringBuffer) buf );
        }
      }
    }
  }

  private void recurseSpaced ( SimpleNode node, StringBuffer buf ) {
    recurseSpaced( node, buf, 0, node.jjtGetNumChildren() );
  }

  /**
   * Iterates over child nodes with a softspace between each node,
   * without a space after the last node.
   */
  private void recurseInterSpaced ( SimpleNode node, StringBuffer buf, 
                                    int start, int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 < cnt && start < end && end <= cnt ) {
      for ( int i = start; i < end - 1; i++ ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i );
        if ( null != c ) {
          c.jjtAccept( this, buf );
          softspace( (StringBuffer) buf );
        }
      }
      node.jjtGetChild( end - 1 ).jjtAccept( this, buf );
    }
  }

  private void recurseInterSpaced ( SimpleNode node, StringBuffer buf ) {
    recurseInterSpaced( node, buf, 0, node.jjtGetNumChildren() );
  }

  private void recurseInterSpaceBreaked ( SimpleNode node, StringBuffer buf, 
                                          int start, int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 >= cnt || start >= end || end > cnt )
      return ;
    if ( (end - start) > 1 ) {
			boolean breaked = false;
      node.jjtGetChild( start ).jjtAccept( this, buf ); // operand
      for ( int i = start + 1; i < end; i += 2 ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i ); // op
        SimpleNode cc = (SimpleNode) node.jjtGetChild( i + 1 ); // operand
        if ( null != c && null != cc ) {
					softspace( buf );
          c.jjtAccept( this, buf );
					softspace( buf );
          cc.jjtAccept( this, buf );
          if ( MAXCOL <= _col ) {
						if ( ! breaked ) {
							breaked = true;
							indent( buf );
						}
						softnewline( buf );
          }
        }
      }
			if ( breaked )
				outdent();
    } else {
      recurseInterSpaced( node, buf, start, end );
    }
  }

  private void recurseInterSpaceBreaked ( SimpleNode node, StringBuffer buf ) {
    recurseInterSpaceBreaked( node, buf, 0, node.jjtGetNumChildren() );
  }

  private void recurseCommaList ( SimpleNode node, StringBuffer buf, int start, 
                                  int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 >= cnt || start >= end || end > cnt )
      return ;
    if ( (end - start) > 1 ) {
			boolean breaked = false;
      node.jjtGetChild( start ).jjtAccept( this, buf ); // operand
      for ( int i = start + 1; i < end; i += 2 ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i ); // comma
        SimpleNode cc = (SimpleNode) node.jjtGetChild( i + 1 ); // operand
        if ( null != c && null != cc ) {
          c.jjtAccept( this, buf );
          if ( MAXCOL <= _col ) {
						if ( ! breaked ) {
							breaked = true;
							indent( buf );
						}
            softnewline( buf );
          }
          cc.jjtAccept( this, buf );
        }
      }
			if ( breaked )
				outdent();
    } else {
      recurseInterSpaced( node, buf, start, end );
    }
  }

  private void recurseCommaList ( SimpleNode node, StringBuffer buf ) {
    recurseCommaList( node, buf, 0, node.jjtGetNumChildren() );
  }

  private void recurse ( SimpleNode node, StringBuffer buf, int start, int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 < cnt ) {
      for ( int i = start; i < end; i++ ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i );
        if ( null != c )
          c.jjtAccept( this, buf );
        
      }
    }
  }

  private void recurse ( SimpleNode node, StringBuffer buf ) {
    recurse( node, buf, 0, node.jjtGetNumChildren() );
  }

  private void check ( SimpleNode node, Object data ) {
    if ( null == data || !(data instanceof StringBuffer) ) {
      System.out.println( "Abnormal termination: Must pass StringBuffer in visit." );
      System.exit( -1 );
    }
    printSpecialTokens( node, (StringBuffer) data );
  }

  private void styleWarning ( String message ) {
    System.err.println( "WARNING (" + _row + "," + _col + "): " + message
                         + "  is strongly discouraged as a matter of style." );
  }

  public Object visit ( SimpleNode node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeCompilationUnit node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    recurse( node, (StringBuffer) data, 1, node.jjtGetNumChildren() );
    softnewline( (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeModifiers node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePackageDeclaration node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    softspace( (StringBuffer) data );
    recurse( node, (StringBuffer) data, 1, node.jjtGetNumChildren() );
    newline( (StringBuffer) data );
    newline( (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeImportDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    StringBuffer buf = new StringBuffer();
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, buf );
    softspace( buf );
    recurse( node, buf, 1, node.jjtGetNumChildren() );
    out( (StringBuffer) data, buf.toString() );
    if ( node.jjtGetChild( cnt - 2 ) instanceof NodeToken )
      styleWarning( "The use of package imports ( " + buf.toString() + " )" );
    return data;
  }

  public Object visit ( NodeTypeDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeClassDeclaration node, Object data ) {
    newline( (StringBuffer) data );
    check( node, data );
    Node child = node.jjtGetChild( 0 );
    child = null == child
            ? null
            : child.jjtGetChild( 0 );
    Token jdoc = null == child
                 ? null
                 : ((SimpleNode) child).getToken();
    jdoc = null == jdoc
           ? null
           : jdoc.specialToken;
    if ( null == jdoc )
      out( (StringBuffer) data, JDOC_START + JDOC_CLASS_DECL + JDOC_END );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeUnmodifiedClassDeclaration node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    recurseSpaced( node, (StringBuffer) data, 0, 2 ); // class xyz
    if ( 4 < cnt ) { // extends ...
    
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurseSpaced( node, (StringBuffer) data, 2, 4 );
      if ( 6 < cnt ) { // implements ...
      
        softnewline( (StringBuffer) data );
        recurseSpaced( node, (StringBuffer) data, 4, 6 );
      }
      outdent();
      softnewline( (StringBuffer) data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data ); // ClassBody()
    return data;
  }

  public Object visit ( NodeClassBody node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 2 < cnt ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurse( node, (StringBuffer) data, 1, cnt - 1 );
      outdent();
      softnewline( (StringBuffer) data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeNestedClassDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeClassBodyDeclaration node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeMethodDeclarationLookahead node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeInterfaceDeclaration node, Object data ) {
    newline( (StringBuffer) data );
    check( node, data );
    Node child = node.jjtGetChild( 0 );
    child = null == child
            ? null
            : child.jjtGetChild( 0 );
    Token jdoc = null == child
                 ? null
                 : ((SimpleNode) child).getToken();
    jdoc = null == jdoc
           ? null
           : jdoc.specialToken;
    if ( null == jdoc )
      out( (StringBuffer) data, JDOC_START + JDOC_CLASS_DECL + JDOC_END );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeNestedInterfaceDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeUnmodifiedInterfaceDeclaration node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    recurseSpaced( node, (StringBuffer) data, 0, 2 ); // interface xyz
    int bpos = node.jjtGetChild( 3 ) instanceof NodeNameList
               ? 4
               : 2;
    if ( 4 == bpos ) { // extends...
    
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurseInterSpaced( node, (StringBuffer) data, 2, 4 );
      outdent();
      softnewline( (StringBuffer) data );
    }
    node.jjtGetChild( bpos ).jjtAccept( this, data ); // lbrace
    indent( (StringBuffer) data );
    recurse( node, (StringBuffer) data, bpos + 1, cnt - 1 );
    outdent();
    softnewline( (StringBuffer) data );
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data ); // rbrace
    return data;
  }

  public Object visit ( NodeInterfaceMemberDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeFieldDeclaration node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    softspace( (StringBuffer) data );
    node.jjtGetChild( 1 ).jjtAccept( this, data );
    recurse( node, (StringBuffer) data, 2, node.jjtGetNumChildren() );
    return data;
  }

  public Object visit ( NodeVariableDeclaratorList node, Object data ) {
    check( node, data );
    recurseCommaList( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeVariableDeclarator node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeVariableDeclaratorId node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    if ( 1 < cnt ) // with array dims
    
      recurse( node, (StringBuffer) data, 1, cnt );
    softspace( (StringBuffer) data );
    node.jjtGetChild( 0 ).jjtAccept( this, data ); // identifier
    return data;
  }

  public Object visit ( NodeVariableInitializer node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeArrayInitializer node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    //ST_LBRACE() [ VariableInitializer() ( LOOKAHEAD(2) ST_COMMA() VariableInitializer() )* ] [ ST_COMMA() ] ST_RBRACE()
    node.jjtGetChild( 0 ).jjtAccept( this, data ); // LBRACE
    boolean hasTrailingComma = node.jjtGetChild( cnt - 2 ) instanceof NodeToken
                               &&
                               ",".equals( 
                               ((SimpleNode) node.jjtGetChild( cnt - 2 )).getToken().image );
    if ( 2 < cnt ) {
      softspace( (StringBuffer) data );
      recurseCommaList( node, (StringBuffer) data, 1, hasTrailingComma
                                                       ? cnt - 2
                                                       : cnt - 1 );
      softspace( (StringBuffer) data );
    }
    if ( hasTrailingComma )
      node.jjtGetChild( cnt - 2 ).jjtAccept( this, data ); // [COMMA]
      
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data ); // RBRACE
    return data;
  }

  public Object visit ( NodeMethodDeclaration node, Object data ) {
    out( (StringBuffer) data, "\n" );
    softnewline( (StringBuffer) data );
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    boolean hasBlock = node.jjtGetChild( cnt - 1 ) instanceof NodeBlock;
    if ( hasBlock && (node.jjtGetChild( cnt - 2 ) instanceof NodeNameList) ) {
      recurseInterSpaced( node, (StringBuffer) data, 0, cnt - 3 );
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurseInterSpaced( node, (StringBuffer) data, cnt - 3, cnt - 1 );
      outdent();
      softnewline( (StringBuffer) data );
    } else {
      recurseInterSpaced( node, (StringBuffer) data, 0, cnt - 1 );
    }
    if ( hasBlock ) 
      softspace( (StringBuffer) data );
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeMethodDeclarator node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeFormalParameters node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    softspace( (StringBuffer) data );
    if ( 2 < cnt ) {
      node.jjtGetChild( 0 ).jjtAccept( this, data );
      softspace( (StringBuffer) data );
      recurseCommaList( node, (StringBuffer) data, 1, cnt - 1 );
      softspace( (StringBuffer) data );
      node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    } else {
      recurse( node, (StringBuffer) data );
    }
    return data;
  }

  public Object visit ( NodeFormalParameter node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    if ( 2 < cnt ) {
      node.jjtGetChild( 0 ).jjtAccept( this, data );
      softspace( (StringBuffer) data );
    }
    recurse( node, (StringBuffer) data, cnt - 2, cnt );
    return data;
  }

  public Object visit ( NodeConstructorDeclaration node, Object data ) {
    softnewline( (StringBuffer) data );
    newline( (StringBuffer) data );
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeUnmodifiedConstructorDeclaration node, Object data ) {
    check( node, data );
		int cnt = node.jjtGetNumChildren();
		if ( 3 < cnt ) {
			recurse( node, (StringBuffer) data, 0, 2 ); // id, formal parms
			indent( (StringBuffer) data );
			softnewline( (StringBuffer) data );
			recurseInterSpaced( node, (StringBuffer) data, 2, 4 ); // throws, namelist
			outdent();
			softnewline( (StringBuffer) data );
			node.jjtGetChild( 4 ).jjtAccept( this, data ); // body 
		} else {
	    recurse( node, (StringBuffer) data ); // id, formal parms, body
		}
    return data;
  }

  public Object visit ( NodeConstructorBody node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    softspace( (StringBuffer) data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 2 < cnt  ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurse( node, (StringBuffer) data, 1, cnt - 1 );
      outdent();
      softnewline( (StringBuffer) data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeExplicitConstructorInvocation node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeInitializer node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    newline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeType node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePrimitiveType node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeResultType node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeName node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeNameList node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeAssignmentOperator node, Object data ) {
    check( node, data );
    softspace( (StringBuffer) data );
    recurse( node, (StringBuffer) data );
    softspace( (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeConditionalExpression node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    if ( 1 < cnt ) { // Hook expr
			Node condexp = node.jjtGetChild( 4 );
			boolean cascade = (condexp instanceof NodeConditionalExpression) 
				&& ( 1 < condexp.jjtGetNumChildren() );
			recurseInterSpaced( node, (StringBuffer) data, 0, 4 );
			if ( cascade ) {
				indent( (StringBuffer) data );
				softnewline( (StringBuffer) data );
				outdent();
			} else {
				softspace( (StringBuffer) data );
			}
			node.jjtGetChild( 4 ).jjtAccept( this, data );
    } else {
      recurse( node, (StringBuffer) data );
    }
    return data;
  }

  public Object visit ( NodeConditionalOrExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeConditionalAndExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeInclusiveOrExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeExclusiveOrExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeAndExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeEqualityExpression node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeInstanceOfExpression node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeRelationalExpression node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeShiftExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeAdditiveExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeMultiplicativeExpression node, Object data ) {
    check( node, data );
    recurseInterSpaceBreaked( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeUnaryExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePreIncrementExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePreDecrementExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeUnaryExpressionNotPlusMinus node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeCastLookahead node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePostfixExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeCastExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data, 0, 3 );
    softspace( (StringBuffer) data );
    recurse( node, (StringBuffer) data, 3, node.jjtGetNumChildren() );
    return data;
  }

  public Object visit ( NodePrimaryExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePrimaryPrefix node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodePrimarySuffix node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    if ( 3 == cnt )
      recurseInterSpaced( node, (StringBuffer) data );
    else
      recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeLiteral node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeBooleanLiteral node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeNullLiteral node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeArguments node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 2 < cnt ) {
      softspace( (StringBuffer) data );
      node.jjtGetChild( 1 ).jjtAccept( this, data );
      softspace( (StringBuffer) data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeArgumentList node, Object data ) {
    check( node, data );
    if ( 1 < node.jjtGetNumChildren() ) {
      recurseCommaList( node, (StringBuffer) data );
    } else {
      node.jjtGetChild( 0 ).jjtAccept( this, data );
    }
    return data;
  }

  public Object visit ( NodeAllocationExpression node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    out( (StringBuffer) data, " " );
    recurse( node, (StringBuffer) data, 1, node.jjtGetNumChildren() );
    return data;
  }

  public Object visit ( NodeArrayDimsAndInits node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeStatement node, Object data ) {
    check( node, data );
    if ( !(node.jjtGetChild( 0 ) instanceof NodeBlock) )
      softnewline( (StringBuffer) data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeLabeledStatement node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeBlock node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 2 < cnt ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      recurse( node, (StringBuffer) data, 1, cnt - 1 );
      outdent();
      softnewline( (StringBuffer) data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeBlockStatement node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    if ( node.jjtGetChild( cnt - 1 ) instanceof NodeToken )
      softnewline( (StringBuffer) data ); 
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeLocalVariableDeclaration node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data ); // Modifiers
    softspace( (StringBuffer) data );
    node.jjtGetChild( 1 ).jjtAccept( this, data ); // Type
    if ( 3 < cnt )
      recurseCommaList( node, (StringBuffer) data, 2, cnt );
    else
      node.jjtGetChild( 2 ).jjtAccept( this, data ); // VariableDeclarator
      
    return data;
  }

  public Object visit ( NodeEmptyStatement node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    styleWarning( "The use of empty statements" );
    return data;
  }

  public Object visit ( NodeStatementExpression node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeSwitchStatement node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    recurseInterSpaced( node, (StringBuffer) data, 0, 5 );
    indent( (StringBuffer) data );
    for ( int i = 5; i < cnt - 1; i++ ) {
      node.jjtGetChild( i ).jjtAccept( this, data );
      if ( node.jjtGetChild( i ) instanceof NodeSwitchLabel )
        indent( (StringBuffer) data );
      if ( !(node.jjtGetChild( i + 1 ) instanceof NodeBlockStatement) )
        outdent();
      
    }
    outdent();
    softnewline( (StringBuffer) data );
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeSwitchLabel node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    softnewline( (StringBuffer) data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 3 == cnt ) {
      softspace( (StringBuffer) data );
      node.jjtGetChild( 1 ).jjtAccept( this, data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeIfStatement node, Object data ) {
    check( node, data );
    //KT_IF() ST_LPAREN() Expression() ST_RPAREN() Statement() [ LOOKAHEAD(1) KT_ELSE() Statement() ]
    boolean isIfBlock = node.jjtGetChild( 4 ).jjtGetChild( 0 ) instanceof NodeBlock;
    boolean isElseBlock = 5 < node.jjtGetNumChildren()
                           && node.jjtGetChild( 6 ).jjtGetChild( 0 ) instanceof NodeBlock;
    boolean mandatoryBraces = isIfBlock || isElseBlock;
    if ( !isIfBlock && mandatoryBraces )
      ((SimpleNode) node.jjtGetChild( 3 )).getToken().image += " {";
    recurseInterSpaced( node, (StringBuffer) data, 0, 4 );
    if ( !isIfBlock ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      node.jjtGetChild( 4 ).jjtAccept( this, data );
      outdent();
      if ( mandatoryBraces ) {
        softnewline( (StringBuffer) data );
        out( (StringBuffer) data, "}" );
      }
    } else { // Block
      softspace( (StringBuffer) data );
      node.jjtGetChild( 4 ).jjtAccept( this, data );
    }
    if ( 5 < node.jjtGetNumChildren() ) { // else option
      boolean ifSequence = node.jjtGetChild( 6 ).jjtGetChild( 0 ) instanceof NodeIfStatement;
      if ( ! mandatoryBraces )
        softnewline( (StringBuffer) data );
      softspace( (StringBuffer) data );
      if ( !isElseBlock && mandatoryBraces )
        ((SimpleNode) node.jjtGetChild( 5 )).getToken().image += " {";
      node.jjtGetChild( 5 ).jjtAccept( this, data ); // else
      if ( !isElseBlock ) {
        if ( !ifSequence || mandatoryBraces ) {
          indent( (StringBuffer) data );
          softnewline( (StringBuffer) data );
        } else {
          softspace( (StringBuffer) data );
        }
        node.jjtGetChild( 6 ).jjtAccept( this, data );
        if ( !ifSequence || mandatoryBraces )
          outdent();
        if ( mandatoryBraces ) {
          softnewline( (StringBuffer) data );
          out( (StringBuffer) data, "}" );
        }
      } else { // Block
      
        softspace( (StringBuffer) data );
        node.jjtGetChild( 6 ).jjtAccept( this, data );
      }
    }
    return data;
  }

  public Object visit ( NodeWhileStatement node, Object data ) {
    check( node, data );
    recurseSpaced( node, (StringBuffer) data, 0, 4 );
    Node statement = node.jjtGetChild( 4 );
    if ( !(statement.jjtGetChild( 0 ) instanceof NodeBlock) ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      statement.jjtAccept( this, data );
      outdent();
    } else {
      statement.jjtAccept( this, data );
    }
    return data;
  }

  public Object visit ( NodeDoStatement node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    softspace( (StringBuffer) data );
    Node statement = node.jjtGetChild( 1 );
    if ( !(statement.jjtGetChild( 0 ) instanceof NodeBlock) ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      statement.jjtAccept( this, data );
      outdent();
      softnewline( (StringBuffer) data );
    } else {
      statement.jjtAccept( this, data );
    }
    softspace( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data, 2, 6 );
    node.jjtGetChild( 6 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeForStatement node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data, 0, 2 );
    recurseSpaced( node, (StringBuffer) data, 2, 4 );
    Node statement = node.jjtGetChild( 4 );
    if ( !(statement.jjtGetChild( 0 ) instanceof NodeBlock) ) {
      indent( (StringBuffer) data );
      softnewline( (StringBuffer) data );
      statement.jjtAccept( this, data );
      outdent();
    } else {
      statement.jjtAccept( this, data );
    }
    return data;
  }

  public Object visit ( NodeForControl node, Object data ) {
    check( node, data );
    //( [ ForInit() ] ST_SEMICOLON() [ Expression() ] ST_SEMICOLON() [ ForUpdate() ] ) #ForControl(true)
    for ( int i = 0; i < node.jjtGetNumChildren(); i++ ) {
      node.jjtGetChild( i ).jjtAccept( this, data );
      if ( node.jjtGetChild( i ) instanceof NodeToken )
        out( (StringBuffer) data, " " );
      
    }
    return data;
  }

  public Object visit ( NodeForInit node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeStatementExpressionList node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeForUpdate node, Object data ) {
    check( node, data );
    recurse( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeBreakStatement node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 3 == cnt ) {
      softspace( (StringBuffer) data );
      node.jjtGetChild( 1 ).jjtAccept( this, data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeContinueStatement node, Object data ) {
    check( node, data );
    int cnt = node.jjtGetNumChildren();
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    if ( 3 == cnt ) {
      softspace( (StringBuffer) data );
      node.jjtGetChild( 1 ).jjtAccept( this, data );
    }
    node.jjtGetChild( cnt - 1 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeReturnStatement node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    softspace( (StringBuffer) data );
    recurse( node, (StringBuffer) data, 1, node.jjtGetNumChildren() );
    return data;
  }

  public Object visit ( NodeThrowStatement node, Object data ) {
    check( node, data );
    node.jjtGetChild( 0 ).jjtAccept( this, data );
    softspace( (StringBuffer) data );
    node.jjtGetChild( 1 ).jjtAccept( this, data );
    node.jjtGetChild( 2 ).jjtAccept( this, data );
    return data;
  }

  public Object visit ( NodeSynchronizedStatement node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeTryStatement node, Object data ) {
    check( node, data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeCatchBlock node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeFinallyBlock node, Object data ) {
    check( node, data );
    softnewline( (StringBuffer) data );
    recurseInterSpaced( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeToken node, Object data ) {
    check( node, data );
    StringBuffer buf = new StringBuffer( node.getToken().image );
    switch ( node.getToken().kind ) {
      case COMMA:
        buf.append( " " );
        break;
    }
    out( (StringBuffer) data, buf.toString() );
    printEOLComment( node, (StringBuffer) data );
    return data;
  }

  public Object visit ( NodeKeyword node, Object data ) {
    check( node, data );
    out( (StringBuffer) data, node.getToken().image );
    return data;
  }

} // Format

