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
 * 
 * NOTE: This file is an adaption of the WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University
 * This package was released under the Library GPL but maintenance and
 * further development has been discontinued.
 * For a detailed information see http://www.cs.cmu.edu/~rcm/websphinx/
 * and read the README that can be found in this subpackage.
 */
package org.owasp.webscarab.spider;

import java.io.ObjectInputStream;
import java.io.FileInputStream;
import org.owasp.webscarab.util.Timer;

/** 
 * Runs a crawler periodically.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Chronicle 
	extends Timer 
	implements Runnable 
{
	/** the Crawler instance that is triggered periodically */
	private Crawler _crawler;
	/** the time interval given in seconds */
	private int _interval;
	/** flag that denotes whether the Crawler is currently active */
	private boolean _running = false;
	/** flag that denotes whether the Chronicle has been triggered */
	private boolean _triggered = false;
	
	/** 
	 * Makes a Chronicle.
	 * @param crawler Crawler to run periodically
	 * @param interval Invocation interval, in seconds. Crawler is invoked
	 * every interval seconds.  If the crawler is still running
	 * when interval seconds have elapsed, it is aborted.
	 * 
	 */
	public Chronicle ( Crawler crawler, int interval ) {
		_crawler = crawler;
		_interval = interval;
	}

	/** 
	 * Starts chronicling.  Starts a background thread which
	 * starts the crawler immediately, then re-runs the crawler
	 * every interval seconds from now until stop() is called.
	 */
	public void start () {
		if ( _running )
			return;
		_running = true;
		set( _interval * 1000, true );
		Thread thread = new Thread( this, _crawler.getName() );
		thread.start();
	}

	/** Stop chronicling.  Also stops the crawler, if it's currently running. */
	public synchronized void stop () {
		if ( !_running )
			return ;
		_running = false;
		_crawler.stop();
		notify();
		cancel();
	}

	/** 
	 * Background thread that runs the crawler.
	 * Clients shouldn't call this method.
	 */
	public synchronized void run () {
		try {
			while ( _running ) {
				_crawler.run();
				while ( !_triggered ) 
					wait();
				_triggered = false;
			}
		} 
		catch ( InterruptedException e ) {}
	}

	protected synchronized void alarm () {
		_crawler.stop();
		_triggered = true;
		notify();
	}

	// FIXME: connect to some daemon startup ui that runs attack suites periodically
	public static void main ( String[] args )
		throws Exception
	{
		ObjectInputStream in = new ObjectInputStream( new FileInputStream( args[ 0 ] ) );
		Crawler loadedCrawler = (Crawler) in.readObject();
		in.close();
		EventLog.monitor( loadedCrawler );
		Chronicle track = new Chronicle( loadedCrawler, Integer.parseInt( args[ 1 ] ) );
		track.start();
	}
} // class Chronicle

