package org.owasp.codespy;


/** 
 * This base implementation is intended to
 * reference the plain text description of a rule.
 * <p>
 * Extending classes can define any sort of additional information, for
 * example, links to supporting documentation.
 * @author Mark Curphey
 * @version 1.0
 */
public class Reference {
	/** *  Rule in plain text. */
	private String text;
	
	/** 
	 * Contructs a reference with the specified plain text description.
	 * @param text the plain text description of the reference.
	 */
	public Reference ( String text ) {
		this.text = text;
	}

	/** 
	 * Returns the plain text description of the reference.
	 * @return the plain text description of the reference.
	 */
	public final String getText () {
		return text;
	}

	/** 
	 * Return the object representation as a String.
	 * @return the reference text.
	 */
	public final String toString () {
		return text;
	}
}

