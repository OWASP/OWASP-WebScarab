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
package org.owasp.webscarab.ui;

import org.owasp.util.Sys;
import org.owasp.webscarab.util.WebScarabSM;
import org.owasp.webscarab.data.Portal;
import org.owasp.webscarab.data.DbListener;
//import org.owasp.webscarab.proxy.Neighbour;
import org.owasp.webscarab.spider.Tarantula;
//import org.owasp.webscarab.analyse.Spy;
import org.owasp.webscarab.attack.Sandbox;

/**
 * Init must be touched by any ui implementation
 * to ensure that the system is properly initialized.
 *
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public final class Init {

	private final ThreadGroup _group;
	private final Thread[] _threads;
	private static Init _instance;
	private final Portal _portal;

	private final DbListener[] _modules;
	
	/** Avoids external instantiation. */
	private Init () {
		if ( null != _instance )
			throw new SecurityException( "only one Init instance allowed." );
		// the root (ui) thread
		_threads = new Thread[6];
		_threads[ 0 ] = Thread.currentThread();
		_group = new ThreadGroup( "MODULES" );
		
		_portal = new Portal();
		_modules = new DbListener[ 5 ];
		_modules[ 0 ] = null; // new Neighbour( _portal );
		_modules[ 1 ] = new Tarantula( _portal );
		_modules[ 2 ] = null; // new Spy( _portal );
		_modules[ 3 ] = new Sandbox( _portal );
		
		// register modules
/*		for ( int i = 0; i < _modules.length; i++ )
			_portal.register( modules[ i ] ); */
		// FIXME: use loop above
		_portal.register( _modules[ 1 ] );
		
		// set up threading
		_threads[1] = new Thread( _group, _portal, "PORTAL" );
		_threads[1].setPriority( Thread.MAX_PRIORITY );
		_threads[3] = new Thread( _group, _modules[1], "TARANTULA" );
		_threads[5] = new Thread( _group, _modules[3], "SANDBOX" );
/*		for ( int i = 1; i < _threads.length; i++ )
			_threads[ i ].start(); */
		// FIXME: use loop above
		_threads[1].start();
		_threads[3].start();
		_threads[5].start();
	}

	
	/**
	 * Sets up the basic thread configuration for WebScarab.
	 * Based on this setup, the WebScarabSM will decide which
	 * actions are allowed.
	 */
	public static final synchronized void sinit () {
		if ( null != System.getSecurityManager() )
			Sys.sinitError( Sys.class, "you must not use the default security manager." );
//		System.setSecurityManager( new WebScarabSM( _threads ) );
		_instance = new Init();

	}

	public static final synchronized Portal getPortal () {
		if ( null == _instance )
			throw new IllegalStateException( "getPortal called before sinit completion" );
		return _instance._portal;
	}

	/**
	 * Static initializer.
	 */
	static {
		Sys.sinit( Init.class );
	}
	
} // class Init
