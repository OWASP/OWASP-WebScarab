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
package org.owasp.webscarab.util;

import java.util.PropertyPermission;
import java.io.FileDescriptor;
import java.security.Permission;
import java.security.SecurityPermission;
import java.net.InetAddress;

/** 
 * The global WebScarab security manager.
 * Extends the default security manager in a way that it supports
 * ThreadGroups initiated by certain modules.
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public final class WebScarabSM 
	extends SecurityManager 
{
	private final Thread[] _threads;
	
	public WebScarabSM ( Thread[] threads ) {
		_threads = threads;
	}
	/** Illegal thread, every access forbidden */
	public final static int T_ILLEGAL = -1;
	/** 
	 * Root thread (that is UserInterface), some special access rights to
	 * enable JVM startup
	 */
	public final static int T_ROOT = 0;
	/** Database Portal thread */
	public final static int T_DATA = 1;
	/** Spider thread */
	public final static int T_SPIDER = 2;
	/** Proxy thread */
	public final static int T_PROXY = 3;
	/** Analyze thread */
	public final static int T_ANALYZE = 4;
	/** Attack generator ("sandbox") thread */
	public final static int T_ATTACK = 5;
	/** Attack module thread */
	public final static int T_ATTACKM = 6;

	/** 
	 * Returns an integer constant that is assigned to one of the
	 * main modules thread. If this is another thread, it returns
	 * -1;
	 */
	private final int checkThread ( Thread t ) {
		for ( int i = 0; i < _threads.length; i++ ) 
			if ( _threads[ i ] == t )
				return i;
		return T_ILLEGAL;
	}

	/** 
	 * Checks whether a Thread is allowed to accept connections.
	 * This is only allowed for the Sandbox.
	 */
	public final void checkAccept ( String host, int port ) {
		super.checkAccept( host, port );
	}

	/** 
	 * Checks whether Thread manipulation is allowed.
	 * This is only allowed for subthreads of the Sandbox.
	 */
	public final void checkAccess ( Thread t ) {
		super.checkAccess( t );
		if ( 0 == checkThread( Thread.currentThread() ) )
			return ;
		throw new SecurityException( "not allowed." );
	}

	/** 
	 * Checks whether ThreadGroup manipulation is allowed.
	 * This is not allowed at all.
	 */
	public final void checkAccess ( ThreadGroup g ) {
		super.checkAccess( g );
		if ( 0 == checkThread( Thread.currentThread() ) )
			return ;
		throw new SecurityException( "not allowed." );
	}

	/** 
	 * Checks whether access to Awt queues is allowd.
	 * This is only allowed for ui.
	 */
	public final void checkAwtEventQueueAccess () {
		super.checkAwtEventQueueAccess();
	}

	/** 
	 * Checks whether a Thread is allowed to create connections.
	 * This is only allowed for the Sandbox and for the Portal.
	 */
	public final void checkConnect ( String host, int port ) {
		super.checkConnect( host, port );
	}

	public final void checkConnect ( String host, int port, Object context ) {
		super.checkConnect( host, port, context );
	}

	public final void checkCreateClassLoader () {
		super.checkCreateClassLoader();
	}

	public final void checkDelete ( String file ) {
		super.checkDelete( file );
	}

	public final void checkExec ( String cmd ) {
		super.checkExec( cmd );
	}

	public final void checkExit ( int status ) {
		super.checkExit( status );
	}

	public final void checkLink ( String lib ) {
		super.checkLink( lib );
	}

	public final void checkListen ( int port ) {
		super.checkListen( port );
	}

	// this one will be a bit more complicated, since a call to super
	// is impossible
	/* 
	 * public final void checkMemberAccess(Class clazz, int which) {
	 * super.checkMemberAccess(clazz, which);
	 * throw new SecurityException( "not allowed." );
	 * }
	 */
	public final void checkMulticast ( InetAddress maddr ) {
		super.checkMulticast( maddr );
	}

	public final void checkPackageAccess ( String pkg ) {
		super.checkPackageAccess( pkg );
		Permission perm = new RuntimePermission( "accessClassInPackage." + pkg );
		Permission p = new RuntimePermission( "accessClassInPackage.java.*" );
		if ( p.implies( perm ) )
			return ;
		p = new RuntimePermission( "accessClassInPackage.org.owasp.webscarab.*" );
		if ( p.implies( perm ) )
			return ;
		throw new SecurityException( "not allowed." );
	}

	public final void checkPackageDefinition ( String pkg ) {
		super.checkPackageDefinition( pkg );
		throw new SecurityException( "not allowed." );
	}

	public final void checkPermission ( Permission perm ) {
		Thread current = Thread.currentThread();
		Permission p;
		if ( _threads[ T_ROOT ] == current ) {
			// the following two are necessary to get the logging facility running
			p = new SecurityPermission( "getProperty.networkaddress.cache.*" );
			if ( p.implies( perm ) )
				return ;
			p = new PropertyPermission( "sun.net.inetaddr.ttl", "read" );
			if ( p.implies( perm ) )
				return ;
			p = new PropertyPermission( "file.encoding", "read" );
			if ( p.implies( perm ) )
				return ;
			p = new PropertyPermission( "line.separator", "read" );
			if ( p.implies( perm ) )
				return ;
		}
		throw new SecurityException( "not allowed." );
	}

	public final void checkPermission ( Permission perm, Object context ) {
		throw new SecurityException( "not allowed." );
	}

	public final void checkPrintJobAccess () {
		super.checkPrintJobAccess();
	}

	public final void checkPropertiesAccess () {
		super.checkPropertiesAccess();
	}

	public final void checkPropertyAccess ( String key ) {
		super.checkPropertyAccess( key );
	}

	public final void checkRead ( FileDescriptor fd ) {
		super.checkRead( fd );
		throw new SecurityException( "not allowed." );
	}

	public final void checkRead ( String file ) {
		super.checkRead( file );
	}

	public final void checkRead ( String file, Object context ) {
		super.checkRead( file, context );
	}

	public final void checkSecurityAccess ( String target ) {
		super.checkSecurityAccess( target );
	}

	public final void checkSetFactory () {
		super.checkSetFactory();
	}

	public final void checkSystemClipboardAccess () {
		super.checkSystemClipboardAccess();
	}

	public final boolean checkTopLevelWindow ( Object window ) {
		return super.checkTopLevelWindow( window );
	}

	public final void checkWrite ( FileDescriptor fd ) {
		super.checkWrite( fd );
	}

	public final void checkWrite ( String file ) {
		super.checkWrite( file );
	}

	protected final Class[] getClassContext () {
		return super.getClassContext();
	}

	public final Object getSecurityContext () {
		return super.getSecurityContext();
	}

	public final ThreadGroup getThreadGroup () {
		return super.getThreadGroup();
	}

} // class WebScarabSM

