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
package org.owasp.webscarab.util;


/** * Interface for objects stored in a PriorityQueue. */
public interface Prioritized {
	

	/** * Get the priority of the object. */
	long getPriority ();
}

