package org.owasp.codespy;

import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.ClassProxy;

/** 
 * Specifies the interface to perform a rule based evaluation of a class. An
 * implementing class will apply the rule to a class and produce zero to many
 * {@link Result results} which reference the rule, suggest actions to be
 * taken, and possibly automate conformance.
 * @author Mark Curphey
 * @version 1.0
 */
public interface Rule 
	extends Cloneable
// Cloneable for testing purposes only
{
	

	/** 
	 * Returns the reference registered for this rule.
	 * @return the reference registered for this rule.
	 */
	Reference getReference ();
	

	/** 
	 * Indicates if the rule has produced results.
	 * @return <code>true</code> if the rule has produced results. Otherwise
	 * <code>false</code> if the rule did not produce results, has not yet
	 * been evaluated, or the results have been cleared.
	 */
	boolean hasResults ();
	

	/** 
	 * Returns the result set of the rule applied to the target class. The
	 * implementing class is free to implement any type of rule and to
	 * register any number of results. The result set should be cleared upon
	 * each invocation of the evaluation.
	 * @param target the class the rule is applied to.
	 * @return the result set of the rule applied to the target class or
	 * <code>null</code> if the result did not produce results.
	 * @throws ClassNotFoundException if the class loader cannot find the
	 * class.
	 * @throws NoClassDefFoundError if the virtual machine is unable to
	 * resolve the class.
	 */
	Result[] evaluate ( ClassProxy target ) throws ClassNotFoundException, NoClassDefFoundError;
}

