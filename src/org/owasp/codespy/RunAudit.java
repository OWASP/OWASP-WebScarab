package org.owasp.codespy;

import java.io.Serializable;
import java.io.IOException;
import java.util.Vector;
import org.owasp.codespy.Audit;
import org.owasp.codespy.Rule;
import org.owasp.codespy.Result;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Report;
import org.owasp.codespy.Severity;
import org.owasp.codespy.PrintReport;
import org.owasp.codespy.rule.InnerClass;
import org.owasp.codespy.rule.DeclareInnerClass;
import org.owasp.codespy.rule.Implements;
import org.owasp.codespy.rule.Inheritance;
import org.owasp.codespy.rule.ProtectedFields;
import org.owasp.codespy.rule.PublicFields;
import org.owasp.codespy.rule.AccessMethods;
import org.owasp.codespy.rule.FinalClass;
import org.owasp.codespy.rule.FinalMethods;
import org.owasp.codespy.rule.SignedCode;

/** 
 * This class implements <b><i>CodeSpy</b></i>, a simle code checking framework that
 * can be used by WebScarab to parse applets source code.
 * <p>
 * The following actions will be taken
 * <ul>
 * <li>a warning is issued for any non-final protected or package private
 * field.
 * <li>an error is issued for any non-final public field.
 * <li>an error is issued for any non-final public, protected, or package
 * private field access method. For an access method to be recognized, it
 * must follow the <i>JavaBeans</i> naming convention.
 * <li>an error is issued for any non-abstract class with no known direct
 * subclasses that is not declared private and/or final.
 * <li>an error is issued for any non-abstract method not overridden by a
 * known direct subclass that is not declared private and/or final.
 * <li>an error is issued for any inner class declaration.
 * <li>an error is issued for any inner class implementation.
 * <li>an error is issued for any code that is signed if the <i>Java Runtime
 * </i> Environment (JRE) is prior to release 1.2.
 * <li>an error is issued if a class or interface implements or inherits the
 * implementation of <i>java.lang.Cloneable</i>
 * <li>an error is issued if a class or interface implements or inherits the
 * implementation of <i>java.io.Serializable</i>
 * </ul>
 * <p>
 * Rules may be added, modified or removed by manipulating the rules array
 * provided. If rules are added here, the corresponding implementation must
 * be provided in <i>org.owasp.codespy.rule</i>.
 * <p>
 * To run the audit, issue the command
 * <pre><code>java org.owasp.codespy.RunAudit [-f <report-file>] <file>[ <file> [ <file>]]</code></pre>
 * where <file> is any class or archive. Note that each <file> must reside in
 * your CLASSPATH as this process will attempt to load it.
 * <p>
 * The list of classes that are audited comprise the set of known classes.
 * Known classes can be used to gather additional information about each
 * class undergoing audit. Additional information currently consists of
 * direct subclasses. If B is a direct subclass of A, then B must be part of
 * the class audit set that includes A if this fact is to be recognized.
 * @author Mark Curphey
 * @version 1.0
 */
public class RunAudit {
	/** *  The rule chain to implement Cloneable rules. */
	private static final Reference CLONE_REF = new Reference( "Implementing "
	                                                           + Cloneable.class
	                                                           + " is prohibited." );
	private static final Rule[] clone = { new Implements( Cloneable.class, Severity.WARNING, 
	                                                      CLONE_REF ), 
	                                      new Inheritance( Cloneable.class, Severity.WARNING, 
	                                         CLONE_REF ) };
	/** *  The rule chain to implement Serializable rules. */
	private static final Reference SERIALIZE_REF = new Reference( "Implementing "
	                                                               + Serializable.class
	                                                               + " is prohibited." );
	private static final Rule[] serial = { new Implements( Serializable.class, 
	                                                       Severity.WARNING, SERIALIZE_REF ), 
	                                       new Inheritance( Serializable.class, 
	                                          Severity.WARNING,
	                                          SERIALIZE_REF ) };
	/** *  The rule chain to implement final declarations. */
	private static final Rule[] finals = { new FinalClass( Severity.ERROR ), 
	                                       new FinalMethods( Severity.ERROR ) };
	/** *  Report file. */
	private static String reportFile = null;
	/** *  Report title. */
	private static final String title = "OWASP CodeSpy";

	/** 
	 * Perform the audit.
	 * @param args the list of command line arguments.
	 */
	public static void main ( String[] args ) {
		/** *  The rule set used in the audit. */
		Rule[] rules = new Rule[]{ new RuleChain( serial ),  // implements Serializable
		new RuleChain(clone),  // implements Cloneable
		new InnerClass(Severity.ERROR ),  // is inner class
		new DeclareInnerClass(Severity.ERROR ),  // declares inner class
		new ProtectedFields(Severity.WARNING ),  // protected fields
		new PublicFields(Severity.ERROR ),  // public fields
		new AccessMethods(Severity.WARNING ),  // variable access methods
		new RuleChain(finals),  // final classes/methods
		new SignedCode(Severity.ERROR ) // signed code
		      };
		/** *  Determine command line options. */
		args = parseOptions( args );
		/** *  Perform the audit. */
		Audit[] audit = Audit.audit( args, rules );
		Report report = null;
		/** *  Determine report destination. */
		if ( reportFile == null )
			// console
			report = new PrintReport();
		else
			// report file
			try {
				report = new PrintReport( reportFile );
			} 
			catch ( IOException e ) {
				System.err.println( "Failed to contruct the reporter: " + e );
				System.exit( -1 );
			}
		/** *  Report on each class. */
		report.heading( title );
		for ( int i = 0; i < audit.length; i++ ) {
			report.formatClass( audit[ i ].getTarget() ); // class info
			report.notification( audit[ i ] ); // report any notices
			report.warning( audit[ i ] ); // report any warnings
			report.error( audit[ i ] ); // report any errors
			report.terminal( audit[ i ] ); // report anything
			// catastrophic
		}
		report.references(); // list references
		}

	/** 
	 * Determine the command line options. Currently, the only supported
	 * option is <code>-f</code> used to specify a report output file.
	 * @param args the command line options to parse.
	 * @return the remainder of the command line with the known options
	 * parsed out.
	 */
	private static final String[] parseOptions ( String[] args ) {
		Vector v = new Vector();
		for ( int i = 0; i < args.length; i++ ) 
			if ( args[ i ].startsWith( "-" ) ) {
				if ( args[ i ].equals( "-f" ) ) // report output file
					reportFile = args[ ++i ];
				else
					usage( true ); // exit on usage error
					} else {
				v.addElement( args[ i ] ); // must be class or archive
				}
		String[] sa = new String[v.size()];
		v.copyInto( sa );
		return sa;
	}

	/** 
	 * Display runtime usage to standard error.
	 * @param bail if <code>true</code> the program will exit.
	 */
	private static final void usage ( boolean bail ) {
		System.err.println( "java RunAudit [-f report-file] <file> [ <file>[ <file>...]]" );
		if ( bail )
			System.exit( -1 );
	}
}

