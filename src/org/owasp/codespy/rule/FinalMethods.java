package org.owasp.codespy.rule;

import java.lang.reflect.Modifier;
import java.lang.reflect.Method;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule that states that any method not overriden by a subclass
 * must be declared private, abstract, or final.
 * @author Mark Curphey
 * @version 1.0
 */
public class FinalMethods 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final String MSG = "Any method not overriden by a subclass must be declared private, "
	                                   + "abstract, or final.";
	private static final Reference ref = new Reference( MSG );
	
	/** 
	 * Constructs an instance with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public FinalMethods ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result for any method not overridden by a subclass that
	 * that is not declared private, abstract, or final.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = " can be declared private and/or final";
		// abstract, private and/or final classes pass
		if ( Modifier.isFinal( target.getModifiers() )
		      || Modifier.isPrivate( target.getModifiers() )
		      || Modifier.isAbstract( target.getModifiers() ) )
			return ;
		// test each non-final, non-private method for overriding
		Class[] subclasses = target.getSubclasses();
		Method[] methods = target.getDeclaredMethods();
		for ( int i = 0; i < methods.length; i++ ) {
			boolean found = false;
			// skip abstract, final and/or private methods
			if ( Modifier.isFinal( methods[ i ].getModifiers() )
			      || Modifier.isPrivate( methods[ i ].getModifiers() )
			      || Modifier.isAbstract( target.getModifiers() ) )
				continue;
			// test all subclasses
			for ( int j = 0; j < subclasses.length && !found; j++ ) {
				Method[] scdm = subclasses[ j ].getDeclaredMethods();
				for ( int k = 0; k < scdm.length && !found; k++ ) 
					if ( overrides( methods[ i ], scdm[ k ] ) )
						found = true;
			}
			if ( !found )
				addResult( new Result( this, getSeverity() + ": " + methods[ i ] + msg, getSeverity() ) );
		}
	}

	/** 
	 * Tests method sigs for equivalence.
	 * @param m1 superclass method.
	 * @param m2 subclass method.
	 * @return <code>true</code> if the subclass method overrides the
	 * superclass method, <code>false</code> otherwise.
	 */
	private boolean overrides ( Method m1, Method m2 ) {
		// names must match
		if ( !m1.getName().equals( m2.getName() ) )
			return false;
		// return type must be assignable
		if ( !m1.getReturnType().equals( m2.getReturnType() ) )
			return false;
		// parameters must be assignable
		Class[] p1 = m1.getParameterTypes();
		Class[] p2 = m2.getParameterTypes();
		if ( p1.length != p2.length )
			return false;
		for ( int i = 0; i < p1.length; i++ ) 
			if ( !p1[ i ].equals( p2[ i ] ) )
				return false;
		return true;
	}
}

