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
class TimerManager 
	extends Thread 
{
	Timer first,  last;
	
	/* 
	 * static ThreadGroup rootThreadGroup;
	 * static {
	 * rootThreadGroup = Thread.currentThread().getThreadGroup();
	 * while (rootThreadGroup.getParent() != null)
	 * rootThreadGroup = rootThreadGroup.getParent();
	 * }
	 */
	public TimerManager () {
		super( /* rootThreadGroup, */
		"Timer Manager" );
		setDaemon( true );
		start();
	}

	public synchronized void register ( Timer t, long deadline ) {
		t.deadline = deadline;
		delete( t ); // just in case it's already registered
		//System.err.println ("TimerManager: set " + t + " to go off at " + deadline);
		insertion:{
			for ( Timer u = first; u != null; u = u.next ) {
				if ( t.deadline < u.deadline ) {
					if ( u.prev != null )
						u.prev.next = t;
					else
						first = t;
					t.prev = u.prev;
					t.next = u;
					u.prev = t;
					break insertion;
				}
			}
			if ( last != null ) {
				last.next = t;
				t.prev = last;
				t.next = null;
				last = t;
			} else {
				first = last = t;
			}
		}
		//System.err.println ("TimerManager: waking up background thread");
		notifyAll();
	}

	public synchronized void delete ( Timer t ) {
		if ( t.next != null )
			t.next.prev = t.prev;
		if ( t.prev != null )
			t.prev.next = t.next;
		if ( t == last )
			last = t.prev;
		if ( t == first )
			first = t.next;
		t.next = null;
		t.prev = null;
	}
	static final int FOREVER = 60000; // wake up at least every 60 seconds
	

	public synchronized void run () {
		while ( true ) {
			try {
				//System.err.println ("TimerManager: awake");
				if ( first == null ) {
					//System.err.println ("TimerManager: waiting forever");
					wait( FOREVER );
				//System.err.println ("TimerManager: woke up");
				} else {
					Timer t = first;
					long now = System.currentTimeMillis();
					if ( t.deadline <= now ) {
						// System.err.println ("TimerManager: timer " + t + " just went off at " + now);
						try {
							t.isExpired = true;
							t.alarm();
						} 
						catch ( Throwable e ) {
							if ( e instanceof ThreadDeath )
								throw (ThreadDeath) e;
							else
								e.printStackTrace();
						}
						if ( t.periodic ) {
							register( t, now + t.interval );
						} else {
							delete( t );
						}
					} else {
						//System.err.println ("TimerManager: waiting for " + (t.deadline - now) + " msec");
						wait( t.deadline - now );
					//System.err.println ("TimerManager: woke up");
					}
				}
			} 
			catch ( InterruptedException e ) {}
		}
	}
}

