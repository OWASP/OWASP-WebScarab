package org.owasp.codespy.rule;

import java.lang.reflect.Modifier;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule avoiding signed code.
 * This rule only executes for signed code if the rule is executed in a
 * pre-Java 2 runtime. Unfortunetly, this cannot take into consideration the
 * ultimate client runtime. Be warned.
 * @author Mark Curphey
 * @version 1.0
 */
public class SignedCode 
	extends AtomicRule 
{
	/** *  Runtime version indicator. */
	private static String jreVersion = System.getProperty( "java.version" );
	/** *  Reference for the rule. */
	private static final Reference ref = new Reference( "Signed code is prohibited." );
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @param severity the severity to assign infractions.
	 */
	public SignedCode ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class declares signers.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		// only an issue prior to version 1.2
		if ( jreVersion.compareTo( "1.2" ) >= 0 )
			return ;
		String msg = getSeverity() + ": this class is signed by ";
		Object[] signers = target.getSigners();
		for ( int i = 0; signers != null && i < signers.length; i++ ) 
			addResult( new Result( this, msg + signers[ i ], getSeverity() ) );
	}
}

