package org.owasp.codespy.rule;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule avoidng non-final protected fields.
 * @author Mark Curphey
 * @version 1.0
 */
public class ProtectedFields 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final String MSG = "Non-final protected or package private fields are prohibited.";
	private static final Reference ref = new Reference( MSG );
	// test variables
	protected int foo; // should execute on self-reference test
	int bar; // should execute on self-reference test
	final protected int bas = 0; // should not execute on self-reference test
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public ProtectedFields ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class declares non-final protected or
	 * package protected fields.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class allows protected or "
		              + "package private access to field ";
		Field[] fields = target.getDeclaredFields();
		for ( int i = 0; i < fields.length; i++ ) {
			int modifiers = fields[ i ].getModifiers();
			if ( Modifier.isFinal( modifiers ) )
				continue; // rule does not apply to finals
				 else 
			if ( Modifier.isProtected( modifiers ) )
				addResult( new Result( this, msg + fields[ i ].getName(), getSeverity() ) );
			else 
			if ( !Modifier.isPublic( modifiers ) && !Modifier.isPrivate( modifiers ) )
				// package protected by default
				addResult( new Result( this, msg + fields[ i ].getName(), getSeverity() ) );
		}
	}
}

