package org.owasp.webscarab.tool;

import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import org.owasp.webscarab.util.FileUtil;
import org.owasp.webscarab.tool.javaCC.JavaOneDotTwo;
import org.owasp.webscarab.tool.javaCC.ParseException;
import org.owasp.webscarab.tool.javaCC.Format;

/**
 * Formats java source.
 *
 * @since beta 1
 * @version beta 1<br />CVS $Revision: 1.1 $ $Author: istr $
 * @author istr
 */
public class CodeFormat {

  private static final String ID = "org.owasp.webscarab.tool.Format "
                                    + "(for Java1.2 code) ";
                                    
  public static void main ( String[] args ) {
    JavaOneDotTwo parser;
    String filename = null;
    if ( 0 == args.length ) {
      parser = new JavaOneDotTwo( System.in );
      try {
        Format format = new Format( System.out );
        format.print( parser.CompilationUnit() );
      } 
      catch ( ParseException e ) {
        System.err.println( e.getMessage() );
        System.err.println( ID + "encountered errors during parse." );
      }
    } else {
      if ( 1 == args.length ) {
        filename = args[ 0 ];
        System.err.println( ID + " reformats file " + filename + "... " );
        try {
          parser = new JavaOneDotTwo( new FileInputStream( filename ) );
        } 
        catch ( FileNotFoundException e ) {
          System.err.println( ID + "could not find file '" + filename + "'." );
          return ;
        }
        try {
          ByteArrayOutputStream outbuf = new ByteArrayOutputStream();
          Format format = new Format( new PrintStream( outbuf ) );
          format.print( parser.CompilationUnit() );
          FileUtil.setContent( filename, outbuf.toString(), false );
        } 
        catch ( ParseException e ) {
          System.err.println( e.getMessage() );
          System.err.println( ID + "encountered errors during parse." );
        } 
        catch ( IOException e ) {
          System.err.println( e.getMessage() );
          System.err.println( ID + "could not write file '" + filename + "'." );
        }
      } else {
        System.err.println( "Usage of " + ID + "is one of:" );
        System.err.println( " java org.owasp.webscarab.tool.javaCC.Format < inputfile" );
        System.err.println( " OR" );
        System.err.println( " java org.owasp.webscarab.tool.javaCC.Format inputfile" );
        return ;
      }
    }
  }
} // Format

