package org.owasp.codespy.rule;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule avoiding non-final public fields.
 * @author Mark Curphey
 * @version 1.0
 */
public class PublicFields 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final Reference ref = new Reference( "Non-final public fields are prohibited." );
	// test variables
	public int foo; // should execute on self-reference test
	final public int bar = 0; // should not execute on self-reference test
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public PublicFields ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class is declares non-final public fields.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class allows public access to field ";
		Field[] fields = target.getDeclaredFields();
		for ( int i = 0; i < fields.length; i++ ) {
			int modifiers = fields[ i ].getModifiers();
			if ( Modifier.isFinal( modifiers ) )
				continue; // rule does not apply to finals
				 else 
			if ( Modifier.isPublic( modifiers ) )
				addResult( new Result( this, msg + fields[ i ].getName(), getSeverity() ) );
		}
	}
}

