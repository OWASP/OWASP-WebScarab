package org.owasp.codespy;

import org.owasp.codespy.Rule;
import org.owasp.codespy.Severity;

/** 
 * This represents the outcome of an auditing rule applied to a class. A rule
 * is expected to produce no results if a class passes, one or more results
 * of various severity otherwise.
 * <p>
 * The severity of a result can be used to provide the analysis engine with a hint on
 * how the result should be treated or mask out certain
 * results during processing.
 * @see Rule
 * @see Severity
 * @author Mark Curphey
 * @version 1.0
 */
public class Result {
	/** *  Textual description of the result. */
	private String description;
	/** *  Severity of the result. */
	private Severity severity;
	/** *  The rule that triggered the result. */
	private Rule rule;
	
	/** 
	 * Contructs a result with the specified description and severity.
	 * @param rule a reference to the rule that produced the result.
	 * @param description the text description of the result.
	 * @param severity the severity of the problem this result represents.
	 */
	public Result ( Rule rule, String description, Severity severity ) {
		this.rule = rule;
		this.description = description;
		this.severity = severity;
	}

	/** 
	 * Returns the reference to the rule that produced the result.
	 * @return the reference to the rule that produced the result.
	 */
	public final Rule getRule () {
		return rule;
	}

	/** 
	 * Returns the text description of the result.
	 * @return the text description of the result.
	 */
	public final String getDescription () {
		return description;
	}

	/** 
	 * Determines whether the severity of this result is a notification.
	 * @return <code>true</code> if the severity of this result is a
	 * notification, <code>false</code> otherwise.
	 * @see Severity#NOTICE
	 */
	public final boolean isNotification () {
		return severity.isNotification();
	}

	/** 
	 * Determines whether the severity of this result is a warning.
	 * @return <code>true</code> if the severity of this result is a
	 * warning, <code>false</code> otherwise.
	 * @see Severity#WARNING
	 */
	public final boolean isWarning () {
		return severity.isWarning();
	}

	/** 
	 * Determines whether the severity of this result is an error.
	 * @return <code>true</code> if the severity of this result is an
	 * error, <code>false</code> otherwise.
	 * @see Severity#ERROR
	 */
	public final boolean isError () {
		return severity.isError();
	}

	/** 
	 * Determines whether the severity of this result is terminal.
	 * @return <code>true</code> if the severity of this result is
	 * terminal, <code>false</code> otherwise.
	 * @see Severity#TERMINAL
	 */
	public final boolean isTerminal () {
		return severity.isTerminal();
	}

	/** 
	 * Determines whether this result can be ignored.
	 * @return <code>true</code> if this result can be ignored,
	 * <code>false</code> otherwise.
	 * @see Severity#IGNORE
	 */
	public final boolean ignore () {
		return severity.ignore();
	}

	/* 
	 * Returns the string representation of the object. The default behavior
	 * is to return the text description of the result.
	 * @return the text description of the result.
	 */
	public String toString () {
		return getDescription();
	}
}

