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


/**
 * <TODO description>
 *
 * @since <RELEASE>
 * @version <RELEASE><br />$Revision: 1.1 $ $Author: istr $
 * @author <AUTHOR>
 */
public class Timer {
	int interval;
	boolean periodic;
	boolean isExpired = false;
	static TimerManager manager = new TimerManager();
	long deadline;
	Timer next,  prev;
	
	public Timer () {}

	public void set ( int msecDelay, boolean periodic ) {
		interval = msecDelay;
		this.periodic = periodic;
		isExpired = false;
		if ( !manager.isAlive() ) {
			System.err.println( "TimerManager: restarting" );
			manager = new TimerManager();
		}
		manager.register( this, System.currentTimeMillis() + msecDelay );
	}

	public int getInterval () {
		return interval;
	}

	public boolean getPeriodic () {
		return periodic;
	}

	public void cancel () {
		manager.delete( this );
	}

	protected void alarm () {}

	public boolean expired () {
		return isExpired;
	}
/* 
 * public static void main (String[] args) {
 * for (int i=0; i<args.length; ++i) {
 * boolean periodic = (args[i].charAt (0) == 'p');
 * if (periodic) args[i] = args[i].substring (1);
 * new TestTimer (args[i], Integer.parseInt (args[i]), periodic);
 * }
 * while (true) Thread.yield ();
 * }
 */
}

