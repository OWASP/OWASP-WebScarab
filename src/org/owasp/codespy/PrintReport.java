package org.owasp.codespy;

import java.util.Iterator;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.lang.reflect.Modifier;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.IOException;
import org.owasp.codespy.Audit;
import org.owasp.codespy.Rule;
import org.owasp.codespy.Result;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Report;

/** 
 * Generator for audit results.
 * @author Mark Curphey
 * @version 1.0
 */
public class PrintReport 
	implements Report 
{
	/**  The report stream. */
	PrintStream out;
	/**  Maintain a list of cross reference material. */
	Hashtable refs;
	
	/** 
	 * Constructs a report generator with output to the console. All output
	 * will be to {@link java.lang.System#out}.
	 */
	public PrintReport () {
		out = System.out;
		refs = new Hashtable();
	}
	
	/** 
	 * Constructs a report generator with output to a file.
	 * @param filename the filename of the report to generate.
	 * @throws IOException if the specified file cannot be opened for output.
	 */
	public PrintReport ( String filename )
		throws IOException
	{
		out = new PrintStream( new FileOutputStream( new File( filename ) ) );
		refs = new Hashtable();
	}

	/** 
	 * Formats and outputs a report header.
	 * @param title the title for the report.
	 */
	public void heading ( String title ) {
		SimpleDateFormat sdf = new SimpleDateFormat( "yyyy/MM/dd hh:mm:ss z" );
		out.println( title + "\n" + sdf.format( new Date() ) + "\n\n" );
	}

	/** 
	 * Formats and outputs class information. This information consists of
	 * the fully qualified class name, class access modifiers, and any
	 * extends or implements declarations.
	 * @param c the class to format.
	 */
	public final void formatClass ( Class c ) {
		out.println();
		/* *  Class or interface name. */
		String name = c.toString();
		for ( int i = 0; i < (name.length() + 4); i++ ) 
			out.print( "*" );
		out.println();
		out.println( "* " + name + " *" );
		for ( int i = 0; i < (name.length() + 4); i++ ) 
			out.print( "*" );
		out.println();
		// Access modifier.
		out.print( "Declared" );
		if ( Modifier.isPublic( c.getModifiers() ) )
			out.print( " public" );
		else 
		if ( Modifier.isProtected( c.getModifiers() ) )
			out.print( " protected" );
		else 
		if ( Modifier.isPrivate( c.getModifiers() ) )
			out.print( " private" );
		else
			out.print( " package protected" );
		//  Additional modifiers. 
		if ( Modifier.isStatic( c.getModifiers() ) )
			out.print( " static" );
		if ( Modifier.isAbstract( c.getModifiers() ) )
			out.print( " abstract" );
		if ( Modifier.isNative( c.getModifiers() ) )
			out.print( " native" );
		if ( Modifier.isFinal( c.getModifiers() ) )
			out.print( " final" );
		out.println();
		/* *  Superclass. */
		if ( !c.isInterface() )
			// don't give information on extending java.lang.Object
			if ( !Object.class.equals( c.getSuperclass() ) )
				out.println( "Extends " + c.getSuperclass().getName() );
		/* *  Implemented or extended interfaces. */
		Class[] iface = c.getInterfaces();
		if ( iface.length > 0 ) {
			out.print( (c.isInterface()
			               ? "Extends "
			               : "Implements ") );
			for ( int i = 0; i < iface.length; i++ ) 
				out.print( iface[ i ].getName() );
			out.println();
		}
	}

	/** 
	 * Format and output any audit results that issue a warning.
	 * @param audit the results to format and output.
	 * @see Severity#WARNING
	 */
	public final void warning ( Audit audit ) {
		Iterator results = audit.getResults();
		while ( results.hasNext() ) {
			Result result = (Result) results.next();
			if ( result.isWarning() ) {
				// add a reference?
				Reference ref = result.getRule().getReference();
				if ( !refs.containsKey( ref ) )
					refs.put( ref, new Integer( refs.size() + 1 ) );
				out.println( result + " [" + refs.get( ref ) + "]" );
			}
		}
	}

	/** 
	 * Format and output any audit results that issue an error.
	 * @param audit the results to format and output.
	 * @see Severity#ERROR
	 */
	public final void error ( Audit audit ) {
		Iterator results = audit.getResults();
		while ( results.hasNext() ) {
			Result result = (Result) results.next();
			if ( result.isError() ) {
				// add a reference?
				Reference ref = result.getRule().getReference();
				if ( !refs.containsKey( ref ) )
					refs.put( ref, new Integer( refs.size() + 1 ) );
				out.println( result + " [" + refs.get( ref ) + "]" );
			}
		}
	}

	/** 
	 * Format and output any audit results that issue a terminal error.
	 * @param audit the results to format and output.
	 * @see Severity#TERMINAL
	 */
	public final void terminal ( Audit audit ) {
		Iterator results = audit.getResults();
		while ( results.hasNext() ) {
			Result result = (Result) results.next();
			if ( result.isTerminal() ) {
				// add a reference?
				Reference ref = result.getRule().getReference();
				if ( !refs.containsKey( ref ) )
					refs.put( ref, new Integer( refs.size() + 1 ) );
				out.println( result + " [" + refs.get( refs ) + "]" );
			}
		}
	}

	/** 
	 * Format and output any audit results that issue a notice.
	 * @param audit the results to format and output.
	 * @see Severity#NOTICE
	 */
	public final void notification ( Audit audit ) {
		Iterator results = audit.getResults();
		while ( results.hasNext() ) {
			Result result = (Result) results.next();
			if ( result.isNotification() ) {
				// add a reference?
				Reference ref = result.getRule().getReference();
				if ( !refs.containsKey( ref ) )
					refs.put( ref, new Integer( refs.size() + 1 ) );
				out.println( result + " [" + refs.get( ref ) + "]" );
			}
		}
	}

	/** *  Format and output reference information. */
	public void references () {
		out.println( "\nHints:\n------------" );
		Enumeration r = refs.keys();
		Reference[] sorted = new Reference[refs.size()];
		while ( r.hasMoreElements() ) {
			Reference ref = (Reference) r.nextElement();
			int index = ((Integer) refs.get( ref )).intValue();
			sorted[ index - 1 ] = ref;
		}
		for ( int i = 0; i < sorted.length; i++ ) 
			out.println( "[" + (i + 1) + "] " + sorted[ i ] );
	}
}

