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

import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Date;
import java.io.PrintWriter;

/** 
 * Crawling monitor that writes messages to standard output or a file.
 * Acts as both a CrawlListener (monitoring start and end of the crawl)
 * and as a LinkListener (monitoring page retrieval).
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class EventLog 
	implements CrawlListener, LinkListener 
{
	/** writer where events are logged to */
	private PrintWriter writer;
	/** flag whether only network events should be logged */
	boolean onlyNetworkEvents = true;
	
	/** 
	 * Creates an EventLog that writes to standard output.
	 * This is a shortcut for <code>EventLog( System.out )</code>.
	 */
	public EventLog () {
		this( System.out );
	}
	
	/**
	 * Creates an EventLog that writes to a stream.
	 * @param out an OutputStream to be written to
	 */
	public EventLog ( OutputStream out ) {
		writer = new PrintWriter( out, true );
	}
	
	/** 
	 * Creates an EventLog that writes to a file.
	 * NOTE: the file will be overwritten if it already exists.
	 * @param filename path of file to which crawling event messages are written
	 */
	public EventLog ( String filename )
		throws IOException
	{
		writer = new PrintWriter( SecurityPolicy.getPolicy().writeFile( new File( filename ), false ) );
	}

	/** 
	 * Sets whether logger prints only network-related LinkEvents.
	 * If true, then the logger only prints LinkEvents where
	 * LinkEvent.isNetworkEvent() returns true.  If false,
	 * then the logger prints all LinkEvents.  Default is true.
	 * @param flag true if only network LinkEvents should be logged
	 */
	public void setOnlyNetworkEvents ( boolean flag ) {
		onlyNetworkEvents = flag;
	}

	/** 
	 * Test whether logger prints only network-related LinkEvents.
	 * If true, then the logger only prints LinkEvents where
	 * LinkEvent.isNetworkEvent() returns true.  If false,
	 * then the logger prints all LinkEvents.  Default is true.
	 * @return true if only network LinkEvents are logged
	 */
	public boolean getOnlyNetworkEvents () {
		return onlyNetworkEvents;
	}

	/** Notify that the crawler started. */
	public void started ( CrawlEvent event ) {
		writer.println( new Date() + ": *** started " + event._crawler );
	}

	/** Notify that the crawler has stopped. */
	public void stopped ( CrawlEvent event ) {
		writer.println( new Date() + ": *** finished " + event._crawler );
	}

	/** Notify that the crawler's state was cleared. */
	public void cleared ( CrawlEvent event ) {
		writer.println( new Date() + ": *** cleared " + event._crawler );
	}

	/** Notify that the crawler timed out. */
	public void timedOut ( CrawlEvent event ) {
		writer.println( new Date() + ": *** timed out " + event._crawler );
	}

	/** Notify that the crawler paused. */
	public void paused ( CrawlEvent event ) {
		writer.println( new Date() + ": *** paused " + event._crawler );
	}

	/** Notify that a link event occured. */
	public void crawled ( LinkEvent event ) {
		switch ( event._id ) {
			case LinkEvent.RETRIEVING:
			case LinkEvent.DOWNLOADED:
			case LinkEvent.VISITED:
			case LinkEvent.ERROR:
				break;
			default:
				if ( onlyNetworkEvents )
					return ;
				break;
		}
		writer.println( new Date() + ": " + event );
		Throwable exc = event._exception;
		if ( exc != null && !(exc instanceof IOException) )
			exc.printStackTrace( writer );
	}

	/** 
	 * Create a EventLog that prints to standard error and attach it to a crawler.
	 * This is a convenience method.
	 * @param crawler Crawler to be monitored
	 */
	public static void monitor ( Crawler crawler ) {
		EventLog logger = new EventLog( System.err );
		crawler.addCrawlListener( logger );
		crawler.addLinkListener( logger );
	}
}

