/*
 * EventRouter.java
 *
 * Created on 28 June 2002, 14:49
 */
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
package org.owasp.webscarab.ui.swing;
import java.net.URL;
import java.net.MalformedURLException;
import org.owasp.data.Row;
import org.owasp.webscarab.data.Portal;
import org.owasp.webscarab.data.DbListener;
import org.owasp.webscarab.data.Queue;
import org.owasp.webscarab.data.AuditRow;
import org.owasp.webscarab.data.SessionRow;
import org.owasp.webscarab.ui.Init;
import org.owasp.webscarab.ui.swing.util.Module;
import org.owasp.webscarab.ui.swing.util.AuditRowBean;
import org.owasp.webscarab.ui.swing.spider.SpiderTabPane;



/**
 *
 * @author  thp
 * @version 
 */
public class EventRouter implements DbListener {

	private final static Integer UNKNOWN = new Integer( -1 );
    
	private final Portal _portal;
	private final Queue _queue;
	/** flag whether we are alive */
	private boolean _alive;
	/** flag whether we are suspended */
	private boolean _suspend;
	private int _attackSession;
	public final static int IDX_SPIDER_CFG = 0;
	public final static int IDX_SPIDER = 1;
	// and the rest....

  private Module[] _modules;
    
    /** Creates new EventRouter */
    
  public EventRouter() {
        		// not alive before born... ;)
		_alive = false;
		// Enforces to load Init so that the system gets initialized.
		String init = Init.class.getName();
		_portal = Init.getPortal();
		_queue = new Queue( _portal, this );
		_portal.register( this );
		_attackSession = 0;
		_modules = new Module[2];
  }

    public void parseAndPush( String in ) {
		System.err.println( "{GUI  } Try to parse URL: " + in );
		URL url = null;
		try {
			url = new URL( in );
			System.err.println( "{GUI  } Sending '" + url + "' to Portal." );
			AuditRow ar = new AuditRow( new Object[] { null, 
				new Integer( _attackSession ), null, null,
				url, null, this, AuditRow.ST_RUN, null, null, null,
			} );
			_portal.set( this, ar );
			_attackSession++;
		} catch ( MalformedURLException e ) {
			System.err.println( "{GUI  } Illegal URL: " + in );
		}
	}

	public void halt () {
		_portal.set( this, Portal.HALT );
	}
	public void stopPortal() {
		_portal.set( this, Portal.STP_SPIDER );
	}
 

  public void setModule( Module module, int idx ) {
		if ( 0 > idx || idx >= _modules.length )
			throw new IllegalArgumentException( "module index out of range" );
		_modules[ idx ] = module;
  }

// DbPortal impl.

	public String getId () {
		return "UI";
	}

	public Queue getQueue () {
		return _queue;
	}

	public void notify ( int row ) {
		System.err.print( "{GUI  } Portal sent " );
		if ( DB_QUEUE == row )
			System.err.println( "DB_QUEUE signal." );
		if ( DB_UP == row )
			System.err.println( "DB_UP signal." );
		if ( DB_DOWN == row )
			System.err.println( "DB_DOWN signal." );
		if ( START == row ) {
			System.err.println( "START signal." );
			_alive = true;
			return;
		}
		if ( STOP == row ) {
			System.err.println( "STOP signal." );
			_alive = false;
			return;
		}
	}
	
	public void run () {
		while ( _alive ) {
			Row r = null;
			while ( _alive && null == r ) // poll the q
				r = _queue.pull();
			if ( null != r ) {
				System.err.println( "{GUI   } got new row" );
				if ( AuditRow.class == r.getClass() ) {
					AuditRow ar = (AuditRow) r;
					AuditRowBean arb = new AuditRowBean(ar);
					System.err.println( "{PORT } received URL: " + ar.get( 3 ) + " with status " + ar.get( 7 ) );
					RunAnEvent rae = 
						new RunAnEvent( _modules[ IDX_SPIDER ], arb );
				}
			}
		}
	}
}
