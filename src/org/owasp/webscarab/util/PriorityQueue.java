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

import java.util.Iterator;
import java.util.Vector;

/** 
 * Priority queue.  Objects stored in a priority queue must implement
 * the Prioritized interface.
 * 
 */
public class PriorityQueue {
	private Vector q; // the queue of elements
	
	/** * Make an empty PriorityQueue. */
	public PriorityQueue () {
		q = new Vector();
	}
	
	/** 
	 * Make an empty PriorityQueue with an initial capacity.
	 * @param initialCapacity number of elements initially allocated in queue
	 */
	public PriorityQueue ( int initialCapacity ) {
		q = new Vector( initialCapacity );
	}

	/** 
	 * Put an object on the queue.  Doesn't check for
	 * duplicate puts.
	 * @param x object to put on the queue
	 */
	public synchronized void put ( Prioritized x ) {
		int newSize = q.size() + 1;
		q.setSize( newSize );
		long priorityX = x.getPriority();
		int i,  p;
		for (i = newSize - 1, p = ((i + 1) / 2) - 1; // i's parent
		 i > 0 && getPriority( p ) > priorityX; i = p, p = ((i + 1) / 2) - 1 ) 
			q.setElementAt( q.elementAt( p ), i );
		q.setElementAt( x, i );
	}

	/** 
	 * Get object with lowest priority from queue.
	 * @return object with lowest priority, or null if queue is empty
	 */
	public synchronized Object getMin () {
		return !empty() ? q.elementAt( 0 ) : null;
	}

	/** 
	 * Get and delete the object with lowest priority.
	 * @return object with lowest priority, or null if queue is empty
	 */
	public synchronized Object deleteMin () {
		if ( empty() )
			return null;
		Object obj = q.elementAt( 0 );
		deleteElement( 0 );
		return obj;
	}

	/** 
	 * Delete an object from queue.  If object was inserted more than
	 * once, this method deletes only one occurrence of it.
	 * @param x object to delete
	 * @return true if x was found and deleted, false if x not found in queue
	 */
	public synchronized boolean delete ( Prioritized x ) {
		int i = q.indexOf( x );
		if ( i == -1 )
			return false;
		deleteElement( i );
		return true;
	}

	/** * Remove all objects from queue. */
	public synchronized void clear () {
		q.removeAllElements();
	}

	/** 
	 * Enumerate the objects in the queue, in no particular order
	 * @return enumeration of objects in queue
	 */
	public synchronized Iterator elements () {
		return q.iterator();
	}

	/** 
	 * Get number of objects in queue.
	 * @return number of objects
	 */
	public synchronized int size () {
		return q.size();
	}

	/** 
	 * Test whether queue is empty.
	 * @return true iff queue is empty.
	 */
	public synchronized boolean empty () {
		return q.isEmpty();
	}

	/** 
	 * Rebuild priority queuein case the priorities of its elements
	 * have changed since they were inserted.  If the priority of
	 * any element changes, this method must be called to update
	 * the priority queue.
	 */
	public synchronized void update () {
		for ( int i = (q.size() / 2) - 1; i >= 0; --i ) 
			heapify( i );
	}

	final void deleteElement ( int i ) {
		int last = q.size() - 1;
		q.setElementAt( q.elementAt( last ), i );
		q.setElementAt( null, last ); // avoid holding extra reference
		q.setSize( last );
		heapify( i );
	}

	/* Establishes the heap property at i's descendents. */
	final void heapify ( int i ) {
		int max = q.size();
		while ( i < max ) {
			int r = 2 * (i + 1); // right child of i
			int l = r - 1; // left child of i
			int smallest = i;
			long prioritySmallest = getPriority( i );
			long priorityR;
			if ( r < max && (priorityR = getPriority( r )) < prioritySmallest ) {
				smallest = r;
				prioritySmallest = priorityR;
			}
			if ( l < max && getPriority( l ) < prioritySmallest ) {
				smallest = l;
			}
			if ( smallest != i ) {
				swap( i, smallest );
				i = smallest;
			} else {
				break;
			}
		}
	}

	/* Swap elements at positions i and j in the table. */
	final void swap ( int i, int j ) {
		Object tmp = q.elementAt( i );
		q.setElementAt( q.elementAt( j ), i );
		q.setElementAt( tmp, j );
	}

	/* 
	 * Return the priority of the element at position i.  For convenience,
	 * positions beyond the end of the table have infinite priority.
	 */
	final long getPriority ( int i ) {
		return ((Prioritized) q.elementAt( i )).getPriority();
	}
}

