package org.owasp.codespy;

import java.util.List;
import java.util.Iterator;
import java.util.Vector;
import java.util.Enumeration;
import java.util.jar.JarFile;
import java.util.jar.JarEntry;
import java.io.File;
import java.io.IOException;
import org.owasp.codespy.Rule;
import org.owasp.codespy.Result;
import org.owasp.codespy.ClassProxy;

/** 
 * Audit a specified class. This class associates a class with a set of
 * rules and performs an audit of the class. This class also provides methods
 * to load a list of classes and/or archives.
 * @author Mark Curphey
 * @version 1.0
 */
public class Audit {
	/** *  The class to audit. */
	private ClassProxy target;
	/** *  The rule set to apply. */
	private Rule[] rules;
	/** *  The results of the audit. */
	private Vector results;
	/** *  Exception thrown during audit. */
	public final class AuditException 
		extends Exception 
	{
		
		/** *  Constructs an exception with no message text. */
		private AuditException () {
			this( "" );
		}
		
		/** 
		 * Constructs an expection with the given message text.
		 * @param the message text to assign the exception.
		 */
		private AuditException ( String msg ) {
			super( msg );
		}
	}
	
	/** 
	 * Constructs an audit on the specified classes using the rule set given.
	 * @param target the class on which the audit will be performed.
	 * @param rules the rule set applied by the audit process.
	 */
	public Audit ( ClassProxy target, Rule[] rules ) {
		this.target = target;
		this.rules = rules;
		results = new Vector();
	}

	/** 
	 * Returns the proxied class of the audit. Each class is wrapped with a
	 * proxy class which provides additional information not available from
	 * {@link java.lang.Class}. This method returns the wrapped class not
	 * the wrapper class.
	 * @return the actual class to audit (not the proxy class).
	 */
	public final Class getTarget () {
		return target.getProxiedClass();
	}

	/** 
	 * Returns an iterator on the result set of a class audit.
	 * @return an iterator on the result set of a class audit.
	 */
	public Iterator getResults () {
		return results.iterator();
	}

	/** 
	 * Audit a class. This method audits the class with regards to the rule
	 * set and gathers the results of the audit.
	 * @throws AuditException if any uncaught exception is thrown during rule
	 * evaluation.
	 */
	public final void perform ()
		throws AuditException
	{
		try {
			for ( int i = 0; i < rules.length; i++ ) {
				// evaluate the rule
				Result[] r = rules[ i ].evaluate( target );
				// register any results
				for ( int j = 0; j < r.length; j++ ) 
					results.addElement( r[ j ] );
			}
		} 
		catch ( Exception e ) {
			e.printStackTrace();
			throw new AuditException( e.getMessage() );
		}
	}

	/** 
	 * Load the specified class. Note that ClassNotFoundException is swallowed
	 * and an error message is generated instead so that additional classes
	 * may be processed.
	 * @param name fully qualified name of the class to load.
	 * @return the {@link java.lang.Class} object of the class loaded.
	 */
	private static final Class loadClass ( String name ) {
		try {
			return Class.forName( name );
		} 
		catch ( ClassNotFoundException e ) {
			System.err.println( "Failed to load " + name + ": " + e );
			return null;
		}
	}

	/** 
	 * Loads all classes found in an archive. The loaded class is added to
	 * the provided collection of classes under process.
	 * @param archive the JAR filename.
	 * @param list the collection of classes under process.
	 */
	private static final void loadArchive ( String archive, List list ) {
		try {
			JarFile jf = new JarFile( archive );
			Enumeration entries = jf.entries();
			while ( entries.hasMoreElements() ) {
				JarEntry entry = (JarEntry) entries.nextElement();
				// only process class files
				if ( !entry.isDirectory() && entry.getName().endsWith( ".class" ) ) {
					String classname = pathToPackage( entry.getName() );
					list.add( loadClass( basename( classname, ".class" ) ) );
				}
			}
		} 
		catch ( IOException e ) {
			System.err.println( "Unable to read archive file " + archive + ": " + e );
		}
	}

	/** 
	 * Converts a directory path to a package name by replacing all occurances
	 * of the path separator character with ".".
	 * @params path the pathname to convert.
	 * @return the package name corresponding to the pathname.
	 */
	private static final String pathToPackage ( String path ) {
		StringBuffer buffer = new StringBuffer( path );
		for ( int i = 0; i < buffer.length(); i++ ) 
			if ( buffer.charAt( i ) == File.separatorChar )
				buffer.setCharAt( i, '.' );
		return buffer.toString();
	}

	/** 
	 * Strip the specified extension from a pathname.
	 * @param pathname the pathname to be stripped of an extension.
	 * @param extension the extension to be stripped.
	 * @return the result of stripping the extension from pathname.
	 */
	private static final String basename ( String pathname, String extension ) {
		File file = new File( pathname );
		StringBuffer name = new StringBuffer( file.getName() );
		int end = file.getName().indexOf( extension );
		return name.substring( 0, end );
	}

	/** 
	 * Perform an audit of one or more resources.
	 * @param resources one or more class and/or archive files specifying the
	 * classes to be audited.
	 * @param rules the rule set to apply to each class in the audit.
	 * @return the collection of class audits.
	 */
	public static final Audit[] audit ( String[] resources, Rule[] rules ) {
		Vector results = new Vector();
		/** *  Load all classes to be audited. */
		Class[] classes = loadClasses( resources, rules );
		/** *  Audit each class. */
		for ( int i = 0; i < classes.length; i++ ) 
			try {
				/** 
				 * Wrap each class so that additional information can be
				 * provided.
				 */
				Audit a = new Audit( new ClassProxy( classes[ i ], classes ), rules );
				/** *  Perform the audit. */
				a.perform();
				/** *  Register the audit results. */
				results.add( a );
			} 
			catch ( AuditException e ) {
				System.err.println( "Failed to audit " + classes[ i ] + ": " + e );
			}
		return (Audit[]) results.toArray( new Audit[results.size()] );
	}

	/** 
	 * Load all classes and/or archives associating each loaded class with a
	 * set of auditing rules. The classes specified by the resource parameter
	 * will constitute the collection of known classes for this audit.
	 * @params resources the classes and/or packages to be loaded.
	 * @params rules the rule set applied during the audit.
	 * @return a collection of all classes involved in the audit.
	 */
	private static final Class[] loadClasses ( String[] resources, Rule[] rules ) {
		Vector v = new Vector();
		for ( int i = 0; i < resources.length; i++ ) 
			// load a class file
			if ( resources[ i ].endsWith( ".class" ) )
				v.addElement( loadClass( basename( resources[ i ], ".class" ) ) );
			// load an archive of classes
			else 
			if ( resources[ i ].endsWith( ".jar" ) )
				loadArchive( resources[ i ], v );
		return (Class[]) v.toArray( new Class[v.size()] );
	}
}

