/* 
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software
 * Foundation, version 2.
 * 
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.util.test;

/**
 * <TODO description>
 *
 * @since <RELEASE>
 * @version <RELEASE><br />$Revision: 1.1 $ $Author: istr $
 * @author <AUTHOR>
 */
class TestTimer 
	extends Timer 
{
	String message;
	
	public TestTimer ( String message, int millisec, boolean periodic ) {
		this.message = message;
		set( millisec, periodic );
	}

	public void alarm () {
		System.out.println( message );
	}
}

