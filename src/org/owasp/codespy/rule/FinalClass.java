package org.owasp.codespy.rule;

import java.lang.reflect.Modifier;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule that states any non-abstact class with no known
 * subclasses should be declared private or final.
 * @author Mark Curphey
 * @version 1.0
 */
public class FinalClass 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final String MSG = "Non-abstract classes with no known subclass must be declared "
	                                   + "final or private.";
	private static final Reference ref = new Reference( MSG );
	
	/** 
	 * Constructs an instance of the rule with the provided severity.
	 * @severity the severity to assign an infraction.
	 */
	public FinalClass ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class is not final, private, or abstract
	 * and has no known extending classes (ie not a superclass).
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class is not declared final";
		// abstract, private and/or final classes pass
		if ( Modifier.isFinal( target.getModifiers() )
		      || Modifier.isPrivate( target.getModifiers() )
		      || Modifier.isAbstract( target.getModifiers() ) )
			return ;
		// test for subclasses
		if ( target.getSubclasses().length == 0 )
			addResult( new Result( this, msg, getSeverity() ) );
	}
}

