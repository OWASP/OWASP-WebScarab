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


/** 
 * A listener for changes in the db.
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public interface DbListener
	extends Runnable
{
	// special notification indices
	/** notification that indicates that the queue is available */
	int DB_QUEUE = -1;
	/** notification that the db is offline and that i/o may be disabled */
	int DB_DOWN = -2;
	/** notification that the db is online and unrestricted i/o is possible */
	int DB_UP = -3;
	/** notification that the DbListener should start interaction with db */
	int START = -4;
	/** notification that the DbListener should stop any subsequent action */
	int STOP = -5;
	/**
	 * notification that the DbListener should wait for a START notification;
	 * a new DbListener instance that keeps track of a status should be created
	 * with WAIT as the initial status
	 */
	int WAIT = -6;

	/** 
	 * Returns an id for the DbListener. The returned value must be unique within
	 * the database and should be constructed such that the database can verify if
	 * the DbListener is a valid and trusted implementation.
	 * @return a unique identifier
	 */
	String getId ();
	

	/** 
	 * Returns the Queue implementation for the DbListener.
	 * The db will enqueue appropriate Row implementations so that the need of
	 * synchronizing will be minimized.
	 * @return a Queue implementation
	 */
	Queue getQueue ();

	/** 
	 * Notifier to tell the DbListener that some row in the db has changed.
	 * @param rowId the id of the changed row. If negative, this will be interpreted
	 * as a special notification event.
	 */
	void notify ( int rowId );
} // class DbListener

