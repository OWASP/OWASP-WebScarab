package org.owasp.codespy;

import java.util.Collection;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.ClassProxy;

/** 
 * A rule chain is a linear set of rules that can be executed in sequence
 * until one of the rules executes. This can be used to
 * implement the situation:
 * <p><pre><code>
 * if ( A ) then
 * return A';
 * else if ( B ) then
 * return B';
 * else if ( C ) then
 * return C';
 * etc...
 * </code></pre>
 * <p>
 * At most, one rule in the chain produces results.
 * @author Mark Curphey
 * @version 1.0
 */
public final class RuleChain 
	implements Rule 
{
	private Rule[] rules;
	
	/** 
	 * Constructs a chain of the specified rules.
	 * @param rules the rules that comprise the chain.
	 */
	public RuleChain ( Rule[] rules ) {
		this.rules = (rules == null
		                ? new Rule[0]
		                : rules);
	}
	
	/** 
	 * Constructs a chain of the specified rules.
	 * @param rules the rules that comprise the chain.
	 */
	public RuleChain ( Collection rules ) {
		this( (Rule[]) rules.toArray() );
	}

	/** 
	 * Returns the reference registered to the rule that fired in the chain.
	 * @return the reference of the rule that fired or <code>null</code>
	 * if either no rule fired or the chain has not been evaluated.
	 */
	public Reference getReference () {
		for ( int i = 0; i < rules.length; i++ ) 
			if ( rules[ i ].hasResults() )
				return rules[ i ].getReference();
		return null;
	}

	/** 
	 * Indicates if s rule in the chain has produced results.
	 * @return <code>true</code> if a rule has produced results, otherwise
	 * <code>false</code>.
	 */
	public final boolean hasResults () {
		boolean result = false;
		for ( int i = 0; i < rules.length && !result; i++ ) 
			result |= rules[ i ].hasResults();
		return result;
	}

	/** 
	 * Returns the results (possibly empty) of a rule chain applied to the
	 * target class. The results are those of the first rule that produces
	 * results and rule evaluation stops at that point. No other rules are
	 * evaluated.
	 * @param target the class the rule is applied to.
	 * @return the result set of the rule applied to the target class.
	 */
	public Result[] evaluate ( ClassProxy target )
		throws ClassNotFoundException, NoClassDefFoundError
	{
		Result[] results = new Result[0];
		for ( int i = 0; i < rules.length && results.length == 0; i++ ) 
			results = rules[ i ].evaluate( target );
		return results;
	}
}

