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
package org.owasp.webscarab.data.test;

import java.util.*;
import java.io.*;
import junit.framework.*;
import org.owasp.webscarab.data.Queue;
import org.owasp.webscarab.data.AuditRow;

/**
 * Tests for Queue.
 */
public class QueueTest extends TestCase {
 
	Queue _q;
	AuditRow _a, _b, _c;
 
  public QueueTest ( String name ) {
    super( name );
  }
  
  protected void setUp () {
		_q = new Queue( null, null );
		_a = new AuditRow( new Object[] { null, null, null, null,
			null, null, null, null, null, null } );
		_b = new AuditRow( new Object[] { null, null, null, null,
			null, null, null, null, null, null } );
		_c = new AuditRow( new Object[] { null, null, null, null,
			null, null, null, null, null, null } );
  }
 
	protected void tearDown () {
		_q = null;
	}
 
  public static Test suite () {
		TestSuite suite =
			new TestSuite( "Tests for org.owasp.webscarab.data.Queue" );
		suite.addTest( new QueueTest( "testEnqueue" ) );
		suite.addTest( new QueueTest( "testDequeue" ) );
    return suite; 
  }
  
	public void testEnqueue () {
		_q.push( _a );
		_q.push( _b );
		_q.push( _c );
		assertEquals( null, _c.q( null ) );
		assertSame( _c, _b.q( null ) );
		assertSame( _b, _a.q( null ) );
	}
	
	public void testDequeue () {
		_q.push( _a );
		_q.push( _b );
		_q.push( _c );
		assertSame( _a, _q.pull() );
		assertSame( _b, _q.pull() );
		assertSame( _c, _q.pull() );
		assertNull( _q.pull() );
		_q.push( _a );
		_q.pull();
		_q.push( _b );
		assertSame( _b, _q.pull() );
	}
	
} // class QueueTest
