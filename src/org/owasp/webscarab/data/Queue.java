/* 
 * Copyright (c) 2002 owasp.org.
 * This file is part of WebScarab.
 * WebScarab is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * WebScarab is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * The valid license text for this file can be retrieved with
 * the call:   java -cp owasp.jar org.owasp.webscarab.LICENSE
 * 
 * If you are not able to view the LICENSE that way, which should
 * always be possible within a valid and working WebScarab release,
 * please write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.owasp.webscarab.data;

import org.owasp.data.Row;

/** 
 * A Queue used to process rows.
 * The implementations are accessed by exactly one Portal and exactly one
 * DbListener instance. The Queue must be constructed by the Portal for
 * the DbListener.
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto: ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public class Queue {
	
	/** portal with access to this queue */
	private final Portal _portal;
	/** listener with access to this queue */
	private final DbListener _listener;
	/** head pointer */
	private volatile Row _head;
	/** tail pointer */
	private Row _tail;
	
	/**
	 * Constructs a queue with a minimal queue size (limit).
	 * @param portal the portal that uses this queue (push)
	 * @param listener the listener that uses this queue (pull)
	 * @param 
	 */
	public Queue ( Portal portal, DbListener listener ) {
		_portal = portal;
		_listener = listener;
		_head = null;
		_tail = null;
	}

	/** 
	 * Pushes a Row into the Queue to be processed.
	 * @param row the Row instance to be pushed into the Queue
	 */
	public synchronized void push ( Row row ) {
		if ( null != _tail )
			_tail.q( row );
		else 
			_head = row;
		_tail = row;
	}

	/** 
	 * Pulls a Row from the Queue.
	 * @return a Row instance.
	 */
	public synchronized Row pull () {
		Row r;
		r = _head;
		if ( null != r ) {
			_head = _head.q( null );
			if ( null == _head )
				_tail = null;
		}
		return r;
	}

} // class Queue

