package org.owasp.codespy.rule;

import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule that tests for class implementation of cloneable or serializd
 * interface.
 * @author Mark Curphey
 * @version 1.0
 */
public class Implements 
	extends AtomicRule 
{
	/** *  Implementation to be tested for. */
	private Class implement;
	
	/** 
	 * Constucts an instance to test for implementation of the specified
	 * interface.
	 * @param implement the interface implementation to test for.
	 * @param severity the severity to assign an infraction.
	 * @param reference a reference to the rule description.
	 */
	public Implements ( Class implement, Severity severity, Reference reference ) {
		super( reference, severity );
		this.implement = implement;
	}

	/** 
	 * Registers a result if this class implements the specified interface.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class implements " + implement;
		Class[] iface = target.getInterfaces();
		for ( int i = 0; i < iface.length; i++ ) 
			if ( iface[ i ].equals( implement ) )
				addResult( new Result( this, msg, getSeverity() ) );
	}
}

