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
 * Link event.  A LinkEvent is issued when the crawler
 * starts or stops retrieving a link, and when it makes
 * a decision about a link.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class LinkEvent {
	/** the crawler that generated this link event */
	final public Crawler _crawler;
	/** unique (?) id for this link event */
	final public int _id;
	/** the link that triggered this event */
	final public Link _link;
	/** an exception that occured while visiting the associated link */
	final public Throwable _exception;
	
	/** 
	 * No event occured on this link yet. Never delivered in a LinkEvent,
	 * but may be returned by link.getStatus().
	 */
	public static final int NONE = 0;
	/** Link was rejected by shouldVisit() */
	public static final int SKIPPED = 1;
	/** Link has already been visited during the crawl, so it was skipped. */
	public static final int ALREADY_VISITED = 2;
	/** Link was accepted by walk() but exceeds the maximum depth from the start set. */
	public static final int TOO_DEEP = 3;
	/** Link was accepted by walk() and is waiting to be downloaded */
	public static final int QUEUED = 4;
	/** Link is being retrieved */
	public static final int RETRIEVING = 5;
	/** 
	 * An error occurred in retrieving the page.
	 * The error can be obtained from getException().
	 */
	public static final int ERROR = 6;
	/** Link has been retrieved */
	public static final int DOWNLOADED = 7;
	/** Link has been thoroughly processed by crawler */
	public static final int VISITED = 8;
	/** Map from id code (RETRIEVING) to name ("retrieving") */
	public static final String[] EVENT_NAME = { "none", "skipped", "already visited", "too deep", 
		"queued", "retrieving", "error", "downloaded", "visited" };
	
	/** 
	 * Make a LinkEvent.
	 * @param crawler Crawler that generated this event
	 * @param id event code, like LinkEvent.RETRIEVING
	 * @param link Link on which this event occurred
	 */
	public LinkEvent ( Crawler crawler, int id, Link link ) {
		this( crawler, id, link, null );
	}
	
	/** 
	 * Make a LinkEvent for an error.
	 * @param crawler Crawler that generated this event
	 * @param id Event code, usually ERROR
	 * @param link Link on which this event occurred
	 * @param exception Throwable
	 */
	public LinkEvent ( Crawler crawler, int id, Link link, Throwable exception ) {
		if ( 0 > id || EVENT_NAME.length <= id )
			throw new IllegalArgumentException( "illegal event id" );
		if ( null == crawler )
			throw new IllegalArgumentException( "must provide a Crawler instance" );
		_crawler = crawler;
		_id = id;
		_link = link;
		_exception = exception;
	}

	/** Convert this event to a String describing it. */
	public String toString () {
		String result;
		if ( ERROR == _id )
			result = _exception.toString();
		else
			result = EVENT_NAME[ _id ];
		result += " " + _link.toDescription();
		return result;
	}
}

