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

import java.util.HashMap;
import org.owasp.data.DbException;
import org.owasp.data.Row;
import org.owasp.data.Table;
import org.owasp.data.Engine;
import org.owasp.data.TSVEngine;

/** 
 * The db portal. Each class that wants to access the db must implement
 * DbListener and register with the portal before access will be allowed.
 * The portal implementation should ensure, that only trusted and valid
 * DbListener impls will register successfully;
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public final class Portal 
	implements Runnable 
{
	/** the db engine used by the portal. */	
	private final Engine _engine;
	/** a map that holds the registered DbListener instances (modules) */
	private final DbListener[] _modules;
	/** a map that holds the table workers for the registered modules */
	private final HashMap _tables;
	/** a map that holds the queues for the registered modules */
	private final Queue[] _queues;

	/** name for the session table */
	public static final String TABLE_SESSION = "session";

	/** special row to start spider on all queued URLs */
	public static final AuditRow RUN_SPIDER = new AuditRow(
		new Object[] { AuditRow.ID_ALL, AuditRow.ID_ALL, null, null, null, null,
			AuditRow.ST_RUN, null, null, null } );
	/** special row to suspend spider on all queued URLs */
	public static final AuditRow SUS_SPIDER = new AuditRow(
		new Object[] { AuditRow.ID_ALL, AuditRow.ID_ALL, null, null, null, null,
			AuditRow.ST_SUS, null, null, null } );
	/** special row to stop spider on all queued URLs */
	public static final AuditRow STP_SPIDER = new AuditRow(
		new Object[] { AuditRow.ID_ALL, AuditRow.ID_ALL, null, null, null, null,
			AuditRow.ST_STP, null, null, null } );
	/** special row that denotes that spider has finished spidering all queued URLs */
	public static final AuditRow DON_SPIDER = new AuditRow(
		new Object[] { AuditRow.ID_ALL, AuditRow.ID_ALL, null, null, null, null,
			AuditRow.ST_DON, null, null, null } );
	/** special row to halt the system */
	public static final AuditRow HALT = new AuditRow( 
		new Object[] { AuditRow.ID_ALL, AuditRow.ID_ALL, null, null, null, null,
			null, null, null, null } );

	/** class prefix for modules */
	private final static String CLASS_PREF = "org.owasp.webscarab.";
	/** module signature table: module id, class name and table name */
	private final static String[][] MODULE_SIG = {
		{ "Tarantula", CLASS_PREF + "spider.Tarantula", "session" }, // spider
		{ "Neighbour", CLASS_PREF + "proxy.Neighbour", "session" }, // proxy
		{ "Spy", CLASS_PREF + "analyze.Spy", "signature" }, // analyse module
		{ "Sandbox", CLASS_PREF + "attack.Sandbox", "signature" }, // attack execution
		{ "UI", CLASS_PREF + "ui.console.WebScarab", "audit" }, // console (test) user interface
		{ "UI", CLASS_PREF + "ui.swing.EventRouter", "audit" }, // swing user interface	
		{ "UI", CLASS_PREF + "ui.xml.WebScarab", "audit" }, // xml user interface
		{ "UI", CLASS_PREF + "ui.servlet.WebScarab", "audit" }, // servlet engine user interface
	};

	/**
	 * Creates a dbPortal.
	 * The portal tries to get information about a special engine
	 * implementation out of the configuration.
	 * If the configuration information lacks or is malformed,
	 * dbPortal will fall back to a TSVEngine that works on the 
	 * path "/opt/owasp/webscarab/data"
	 */
	public Portal () {
		int len = MODULE_SIG.length;
		_modules = new DbListener[ len ]; // we have five modules to be registered
		_queues = new Queue[ len ]; // we have five queues to be obtained
		_tables = new HashMap( len ); // we expect five tables to be created
		// TODO fetch config and select proper impl.
		if ( false ) {
		} else {
			_engine = new TSVEngine( "/opt/owasp/webscarab/data/" );
		}
		_tables.put( TABLE_SESSION, _engine.get( TABLE_SESSION, 
			new SessionRow( new Object[] { null, null, null, null } ) ) );
	}

	private void schedule ( int mode, Row row ) {
	}

	public void run () {}

	/** 
	 * Registers a DbListener with this Portal.
	 * @param module the DbListener to be registered
	 * @throws IllegalArgumentException if no module is given, the module does not provide
	 * an id, the module is unknown or the module is already registered.
	 */
	public synchronized void register ( DbListener module )
		throws DbException
	{
		if ( null == module )
			throw new IllegalArgumentException( "must provide a module" );
		String id = module.getId();
		if ( null == id )
			throw new IllegalArgumentException( "illegal module: no id available" );
		String mcn = module.getClass().getName();
		for ( int i = 0; i < MODULE_SIG.length; i++ ) {
			int slot = Math.min( i, 4 ); // adjust slot for UI
			if ( MODULE_SIG[ i ][ 0 ].equals( id ) && MODULE_SIG[ i ][ 1 ].equals( mcn ) ) {
				if ( null != _modules[ slot ] )
					if ( _modules[ slot ] != module )
						throw new IllegalArgumentException( "WARNING: Try to register different module '"
							+ id + "'" );
					else
						throw new IllegalArgumentException( "module '" + id + "'already registered" );
				_modules[ slot ] = module;
				_queues[ slot ] = module.getQueue();
				if ( null == module.getQueue() )
					throw new IllegalArgumentException( "ERROR: module does not provide a data queue" );
				// activate module
				System.err.println( "{PORT } registered module " + id + " @ slot " + slot );
				module.notify( DbListener.DB_QUEUE );
				module.notify( DbListener.START );
				return;
			}
		}
		throw new IllegalArgumentException( "WARNING: Try to register unknown module '"
			+ id + "'" );
	}

	/** 
	 * Unregisters the DbListener from this Portal.
	 * Notifications will be stopped and access will be denied for the
	 * given DbListener after a call to this method.
	 * @param module the DbListener to be unregistered
	 * @return true if unregistration succeeded. Unregistration will
	 * fail in general if there are any open Queues or outstanding
	 * changes that will result in notifications to the DbListener.
	 */
	public synchronized boolean unregister ( DbListener module )
		throws DbException
	{
		
		return false;
	}

	/** 
	 * Updates a given Row instance.
	 * The Row will be delivered to the appropriate Table that can
	 * be accessed by the given DbListener.
	 * @param module the DbListener that wants to update the given row
	 * @param row the Row to be updated
	 * @throws DbException if the Row cannot be delivered or access is
	 * not allowed
	 */
	public synchronized void update ( DbListener module, Row row )
		throws DbException
	{
	}

	/** 
	 * Sets a given Row instance.
	 * The Row will be delivered to the appropriate Table that can
	 * be accessed by the given DbListener.
	 * If the row does not exist in the db and needs to be stored
	 * it will be created (like "insert"). If the row already exists
	 * all values except the rowId will be set (like "update"). 
	 * @param module the DbListener that wants to update the given row
	 * @param row the Row to be updated
	 * @throws DbException if the Row cannot be delivered, access is
	 * not allowed or uniqueness constraints are violated
	 */
	public synchronized void set ( DbListener module, Row row )
		throws DbException
	{
	
		Class c = row.getClass();
		if ( RUN_SPIDER == row ) {
			System.err.println( "{PORT } received RUN_SPIDER" );
			_queues[ 0 ].push( row );
			return;
		}
		if ( SUS_SPIDER == row ) {
			System.err.println( "{PORT } received SUS_SPIDER" );
			_queues[ 0 ].push( row );
			return;
		}
		if ( STP_SPIDER == row ) {
			System.err.println( "{PORT } received STP_SPIDER" );
			_queues[ 0 ].push( row );
			return;
		}
		if ( DON_SPIDER == row ) {
			System.err.println( "{PORT } received DON_SPIDER" );
			_queues[ 0 ].push( row );
			return;
		}
		if ( HALT == row ) {
			System.err.println( "{PORT } received HALT - shutting down." );
			_modules[ 0 ].notify( DbListener.STOP );
			_modules[ 4 ].notify( DbListener.STOP );
			return;
		}
		if ( AuditRow.class == c ) {
			AuditRow ar = (AuditRow) row;
			if ( null == ar.get( 7 ) ) { // new URL, no result given 
		//		System.err.println( "{PORT } new start URL inserted: " + ar.get( 3 ) );
				ar.set( 7, AuditRow.ST_RUN );
				_queues[ 0 ].push( ar );
			} else { // some sort of "result"
		//		System.err.println( "{PORT } received URL: " + ar.get( 3 ) + " with status " + ar.get( 7 ) );
				_queues[ 4 ].push( ar );
			}
		} else if ( SessionRow.class == c ) {
			SessionRow sr = (SessionRow) row;
			_queues[ 4 ].push( sr );
			System.err.println( "{PORT } fetched document @URL: " + sr.get( 2 ) );
			// System.err.println( "{PORT } content dump: " + sr.get( 3 ) );
			try {
				((Table) _tables.get( TABLE_SESSION )).set( sr.get( 2 ).toString().getBytes(), sr.get() );
			} catch ( Exception e ) {
				e.printStackTrace( System.err );
			}
		}
	}

	/** 
	 * Gets a given Row instance.
	 * The Row will be get from the appropriate Table that can
	 * be accessed by the given DbListener.
	 * @param module the DbListener that wants to get the given row
	 * @param id the Row to be fetched by id
	 * @throws DbException if the Row cannot be found or access is
	 * not allowed
	 */
	public synchronized Row get ( DbListener module, int id )
		throws DbException
	{
		return null;
	}
} // class Portal

