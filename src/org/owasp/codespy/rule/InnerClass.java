package org.owasp.codespy.rule;

import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule aviding inner classes.
 * @author Mark Curphey
 * @version 1.0
 */
public class InnerClass 
	extends AtomicRule 
{
	/** *  Allows the reference to be shared with {@link DeclaredInnerClass}. */
	static final Reference ref = new Reference( "Inner classes are prohibited." );
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public InnerClass ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class is declared as an inner class by
	 * another class.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class is declared an inner class of ";
		Class declarer = target.getDeclaringClass();
		if ( declarer != null )
			addResult( new Result( this, msg + declarer, getSeverity() ) );
	}
}

