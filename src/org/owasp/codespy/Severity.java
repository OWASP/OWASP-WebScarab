package org.owasp.codespy;


/** 
 * Defines the set of severity levels that rule results may express.
 * @author Mark Curphey
 * @version 1.0
 */
public final class Severity {
	private static final int IGNORE_VAL = 0;
	private static final int NOTICE_VAL = 1;
	private static final int WARNING_VAL = 2;
	private static final int ERROR_VAL = 3;
	private static final int TERMINAL_VAL = 4;
	private static final String[] text = { "IGNORE", "NOTICE", "WARNING", "ERROR", 
	                                       "TERMINAL" };
	private int level;
	
	private Severity ( int level ) {
		this.level = level;
	}
	/** *  Signifies to the analyzer that this result can be ignored. */
	public static final Severity IGNORE = new Severity( IGNORE_VAL );
	/** 
	 * Signifies a notification to the analysis engine. The analysis engine may choose
	 * to ignore the result.
	 */
	public static final Severity NOTICE = new Severity( NOTICE_VAL );
	/** 
	 * Signifies a warning to the analysis engine. The analysis engine may choose not to
	 * act upon the result, but it should not be ignored.
	 */
	public static final Severity WARNING = new Severity( WARNING_VAL );
	/** 
	 * Signifies an error condition that should be acted upon by the
	 * analysis engine.
	 */
	public static final Severity ERROR = new Severity( ERROR_VAL );
	/** 
	 * Signifies an "error in the extreme" condition that must be acted
	 * upon by the analysis engine.
	 */
	public static final Severity TERMINAL = new Severity( TERMINAL_VAL );

	/** 
	 * Return the text representation of the severity level.
	 * @return the text representation of the severity level.
	 */
	public final String toString () {
		return text[ level ];
	}

	/** 
	 * Determines whether the severity of this result is a notification.
	 * @return <code>true</code> if the severity of this result is a
	 * notification, <code>false</code> otherwise.
	 */
	public final boolean isNotification () {
		return level == NOTICE_VAL;
	}

	/** 
	 * Determines whether the severity of this result is a warning.
	 * @return <code>true</code> if the severity of this result is a
	 * warning, <code>false</code> otherwise.
	 */
	public final boolean isWarning () {
		return level == WARNING_VAL;
	}

	/** 
	 * Determines whether the severity of this result is an error.
	 * @return <code>true</code> if the severity of this result is an
	 * error, <code>false</code> otherwise.
	 */
	public final boolean isError () {
		return level == ERROR_VAL;
	}

	/** 
	 * Determines whether the severity of this result is terminal.
	 * @return <code>true</code> if the severity of this result is
	 * terminal, <code>false</code> otherwise.
	 */
	public final boolean isTerminal () {
		return level == TERMINAL_VAL;
	}

	/** 
	 * Determines whether this result can be ignored.
	 * @return <code>true</code> if this result can be ignored,
	 * <code>false</code> otherwise.
	 */
	public final boolean ignore () {
		return level == IGNORE_VAL;
	}
}
