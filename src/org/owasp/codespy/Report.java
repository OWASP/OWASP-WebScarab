package org.owasp.codespy;


/** 
 * This interface specifies that audit
 * reports must report class information, warnings, errors, terminal errors,
 * and notices for each class in the audit.
 * @author Mark Curphey
 * @version 1.0
 */
public interface Report {
	

	/** 
	 * Format and output a report heading.
	 * @param title the title for the report.
	 */
	void heading ( String title );
	

	/** 
	 * Format and output class information.
	 * @param c the class to format information for.
	 */
	void formatClass ( Class c );
	

	/** 
	 * Format and output warning information.
	 * @param audit the audit to report warnings for.
	 */
	void warning ( Audit audit );
	

	/** 
	 * Format and output error information.
	 * @param audit the audit to report errors for.
	 */
	void error ( Audit audit );
	

	/** 
	 * Format and output terminal error information.
	 * @param audit the audit to report terminal errors for.
	 */
	void terminal ( Audit audit );
	

	/** 
	 * Format and output notice information.
	 * @param audit the audit to report notices for.
	 */
	void notification ( Audit audit );
	

	/**  Format and output reference information. */
	void references ();
}

