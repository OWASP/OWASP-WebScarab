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


/** 
 * Crawling event.  CrawlEvents are broadcast when the
 * crawler starts, stops, or clears its state.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class CrawlEvent {
	/** the Crawler that generated this CrawlEvent */
	final public Crawler _crawler;
	/** identifier for this CrawlEvent; one of [STARTED,STOPPED,CLEARED,TIMED_OUT,PAUSED] */
	final public int _id;
	/** Crawler started. */
	public static final int STARTED = 0;
	/** Crawler ran out of links to crawl */
	public static final int STOPPED = 1;
	/** Crawler's state was cleared. */
	public static final int CLEARED = 2;
	/** Crawler timeout expired. */
	public static final int TIMED_OUT = 3;
	/** Crawler was paused. */
	public static final int PAUSED = 4;
	/** Map from id code (RETRIEVING) to name ("retrieving") */
	public static final String[] EVENT_NAME = { "started", "stopped", "cleared", "timed out", 
		"paused" };
		
	/** 
	 * Make a CrawlEvent.
	 * @param crawler Crawler that generated this event
	 * @param id event id (one of STARTED, STOPPED, etc.)
	 */
	public CrawlEvent ( Crawler crawler, int id ) {
		if ( 0 > id || EVENT_NAME.length <= id )
			throw new IllegalArgumentException( "illegal event id" );
		if ( null == crawler )
			throw new IllegalArgumentException( "must provide a Crawler instance" );
		_crawler = crawler;
		_id = id;
	}

} // class CrawlEvent

