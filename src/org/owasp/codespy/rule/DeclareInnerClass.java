package org.owasp.codespy.rule;

import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule that states it is prohibited for a class to declare an
 * inner class.
 * @author Mark Curphey
 * @version 1.0
 */
public class DeclareInnerClass 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final Reference ref = InnerClass.ref;
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public DeclareInnerClass ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class declares as an inner class.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class declares inner ";
		Class[] declared = target.getDeclaredClasses();
		StringBuffer text = new StringBuffer();
		for ( int i = 0; i < declared.length; i++ ) 
			addResult( new Result( this, msg + declared[ i ], getSeverity() ) );
	}
}

