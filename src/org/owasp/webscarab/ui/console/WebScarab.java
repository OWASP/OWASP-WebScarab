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
package org.owasp.webscarab.ui.console;

import java.util.HashMap;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.MalformedURLException;
import org.owasp.data.Row;
import org.owasp.webscarab.data.Portal; 
import org.owasp.webscarab.data.DbListener;
import org.owasp.webscarab.data.Queue;
import org.owasp.webscarab.data.AuditRow;
import org.owasp.webscarab.ui.Init;

/**
 * A simple console ui that works on stdin / stdout.
 *
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public class WebScarab
	extends Thread
	implements DbListener
{



	private final Portal _portal;
	private final Queue _queue;
	/** flag whether we are alive */
	private boolean _alive;
	/** flag whether we are suspended */
	private boolean _suspend;
	private int _attackSession;

	private final static Integer UNKNOWN = new Integer( -1 );

	private WebScarab ( String[]  args ) {
		// not alive before born... ;)
		_alive = false;
		// Enforces to load Init so that the system gets initialized.
		String init = Init.class.getName();
		_portal = Init.getPortal();
		_queue = new Queue( _portal, this );
		_portal.register( this );
		_attackSession = 0;
	}
	

	// parses an URI and pushes an AuditRow
	private void parseAndPush( String in ) {
		System.err.println( "{UI   } Try to parse URL: " + in );
		URL url = null;
		try {
			url = new URL( in );
			System.err.println( "{UI   } Sending '" + url + "' to Portal." );
			AuditRow ar = new AuditRow( new Object[] { null,
				new Integer( _attackSession ), null, null,
				url, null, this, AuditRow.ST_RUN, null, null, null,
			} );
			_portal.set( this, ar );
			_attackSession++;
		} catch ( MalformedURLException e ) {
			System.err.println( "{UI   } Illegal URL: " + in );
		}
	}

	public void run () {
		while ( ! _alive ); // wait for Portal to start us
		System.out.println( "{UI   } Starting WebScarab..." );
		System.out.println( "{UI   } Enter some URL(s) to be spidered or an empty line to stop." );
		LineNumberReader rd = new LineNumberReader( new InputStreamReader( System.in ) );
		while ( _alive ) {
			try { 
				if ( 0 < System.in.available() ) {
					String in = rd.readLine();
					if ( 0 == in.length() )
						_portal.set( this, Portal.HALT );
					else
						parseAndPush( in );
				}
				Row r = _queue.pull();
				if ( null != r ) {
					System.out.println( "{UI   } Got new row." );
				}
			} catch ( IOException e ) {}
			
		}
		System.out.println( "{UI   } WebScarab stopped." );
	}

// DbPortal impl.

	public String getId () {
		return "UI";
	}

	public Queue getQueue () {
		return _queue;
	}

	public void notify ( int row ) {
		System.err.print( "{UI   } Portal sent " );
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

// static main stuff

	public static void usage () {
		System.err.println( "usage: java -cp {CLASSPATH} " 
			+ "org.owasp.webscarab.ui.console.WebScarab {spiderURL}\n"
			+ "hit some key to stop\n"
			+ "have a look at /opt/owasp/webscarab/data/spider.tsv" );
	}


	public static void main ( String[] args ) {
		try {
			WebScarab me = new WebScarab( args );
			me.start();	
		} catch ( IllegalArgumentException e ) {
			e.printStackTrace( System.err );
			usage();
		}
	}
	
} // class WebScarab
