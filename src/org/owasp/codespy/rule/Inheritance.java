package org.owasp.codespy.rule;

import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule to test the class for inherited implementation of cloneable and serializeable
 * interfaces.
 * @author Mark Curphey
 * @version 1.0
 */
public class Inheritance 
	extends AtomicRule 
{
	/** *  The interface to test for. */
	private Class implement;
	
	/** 
	 * Construct an instance of the rule testing for the specified interface.
	 * @param implement the interface to test for.
	 * @param severity the severity to assign an infraction.
	 * @param reference a reference to the rule description.
	 */
	public Inheritance ( Class implement, Severity severity, Reference reference ) {
		super( reference, severity );
		this.implement = implement;
	}

	/** 
	 * Registers a result if this class inherits the specified interface.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity() + ": this class inherits " + implement + " from ";
		Class offender = search( target.getProxiedClass() );
		if ( offender != null )
			addResult( new Result( this, msg + offender, getSeverity() ) );
	}

	/** 
	 * A recursive search of the class and interface heirarchy to locate
	 * any implementation of the sought after interface.
	 * @param c the class or interface to seed the search.
	 * @return the class or interface that implements or extends the sought
	 * after interface or <code>null</code> if no such class or interface
	 * can be located.
	 */
	private final Class search ( Class c ) {
		if ( c == null )
			return null;
		// Test interfaces.
		Class[] iface = c.getInterfaces();
		for ( int i = 0; i < iface.length; i++ ) 
			if ( iface[ i ].equals( implement ) ) {
				return c; // found it
				} else {
				// try super interface
				Class match = search( iface[ i ] );
				if ( match != null )
					return match;
			}
		// try superclass
		return search( c.getSuperclass() );
	}
}

