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
package org.owasp.webscarab.spider;

import java.util.HashMap;
import java.util.Iterator;
import java.net.URL;
import org.owasp.data.Row;
import org.owasp.webscarab.data.Portal;
import org.owasp.webscarab.data.DbListener;
import org.owasp.webscarab.data.Queue;
import org.owasp.webscarab.data.SessionRow;
import org.owasp.webscarab.data.AuditRow;

/** 
 * Tarantula is the spider implementation based on Crawler.
 * Tarantula listens at the db Portal for incoming AuditRows
 * and starts a new Crawler for every suiteid. It pushes back
 * the URLs together with the content to the db portal.
 * 
 * @since 0.poc
 * @version 0.poc<br />CVS $Release$ $Author: istr $
 * @author <a href="mailto:ingo@ingostruck.de">ingo@ingostruck.de</a>
 */
public final class Tarantula 
	implements DbListener, Runnable, CrawlListener, LinkListener 
{
	/** input queue for Portal */
	private final Queue _queue;
	/** Portal this Tarantula is attached to */
	private final Portal _portal;
	/** Map containing the Crawler instances */
	private HashMap _crawlers;
	/** flag to denote whether the Tarantula is "alive" (not stopped) */
	private boolean _alive;

	/**
	 * Creates a Tarantula that is attached to some Portal.
	 * @param portal the Portal to attach to
	 */
	public Tarantula ( Portal portal ) {
		_alive = false;
		if ( null == portal )
			throw new IllegalArgumentException( "must provide a portal" );
		_portal = portal;
		_queue = new Queue( _portal, this );
		_crawlers = new HashMap();
	}

	/** Stops all Crawlers */
	private void stopAllCrawlers () {
		synchronized ( _crawlers ) {
			Iterator it = _crawlers.values().iterator();
			while ( it.hasNext() ) {
				Crawler c = (Crawler) it.next();
				if ( null == c )
					continue;
				c.stop();
				c.clear();
			}
		}
		System.err.println( "{TARAN} stopped all Crawlers." );
	}

	/** Suspends all Crawlers */
	private void suspAllCrawlers () {
		synchronized ( _crawlers ) {
			Iterator it = _crawlers.values().iterator();
			while ( it.hasNext() ) {
				Crawler c = (Crawler) it.next();
				if ( null != c )
					c.pause();
			}
		}
		System.err.println( "{TARAN} suspended all Crawlers." );
	}

	/** Starts all Crawlers */
	private void startAllCrawlers () {
		synchronized ( _crawlers ) {
			Iterator it = _crawlers.values().iterator();
			while ( it.hasNext() ) {
				Crawler c = (Crawler) it.next();
				if ( null == c )
					c.run();
			}
		}
		System.err.println( "{TARAN} started all Crawlers." );
	}

	// Runnable impl	

	/** starts the Tarantula activity */
	public void run () {
		while ( _alive ) {
			Row r = null;
			while ( _alive && null == r ) // poll the q
				r = _queue.pull();
			if ( null != r ) {
				System.err.println( "{TARAN} got new row" );
				if ( AuditRow.class == r.getClass() ) {
					AuditRow ar = (AuditRow) r;
					Integer sid = (Integer) ar.get( 0 );
					Integer st = (Integer) ar.get( 6 );
					if ( AuditRow.ID_ALL == sid ) {
						if ( AuditRow.ST_RUN == st )
							startAllCrawlers();
						else if ( AuditRow.ST_SUS == st )
							suspAllCrawlers();
						else if ( AuditRow.ST_STP == st )
							stopAllCrawlers();
					} else {
						Crawler c = (Crawler) _crawlers.get( ar.get( 0 ) );	
						if ( null == c ) {
							if ( AuditRow.ST_RUN == st ) {
								c = new Crawler();
								c.setDomain( Crawler.SUBTREE );
								c.setLinkType( Crawler.ALL_LINKS );
								DownloadParameters dp = c.getDownloadParameters();
								dp = dp.changeUserAgent( "Mozilla/5.0 (compatible; WebScarab; Linux)" );
								c.setDownloadParameters( dp );
								c.addCrawlListener( this );
								c.addLinkListener( this );
								_crawlers.put( r.get( 0 ), c );
								c.setRoot( new Link( (URL) ar.get( 3 ) ) );	
								Thread t = new Thread( c, "CRAWL: " + ar.get( 3 ) );
								t.setDaemon( true );
								t.start();
							}
						} else {
							if ( AuditRow.ST_RUN == st ) {
								URL u = (URL) ar.get( 3 );
								if ( null != u ) {
									c.pause();
									c.addRoot( new Link( u ) );
								}
								c.run();
							}
							else if ( AuditRow.ST_SUS == st ) {
								c.pause();
							} 
							else if ( AuditRow.ST_STP == st ) {
								c.stop();
								c.clear();
							} 
						}
					}
				}
			}
		}
	}

	// DbListener impl

	/** 
	 * Returns an id for the DbListener. The returned value must be unique within
	 * the database and should be constructed such that the database can verify if
	 * the DbListener is a valid and trusted implementation.
	 * @return a unique identifier
	 */
	public final String getId () {
		return "Tarantula";
	}

	/** 
	 * Returns the Queue implementation for the DbListener.
	 * The db will enqueue appropriate Row implementations so that the need of
	 * synchronizing will be minimized.
	 * @return a Queue implementation
	 */
	public Queue getQueue () {
		return _queue;
	}

	/** 
	 * Notifier to tell the DbListener that some row in the db has changed.
	 * @param rowId the id of the changed row. If negative, this will be interpreted
	 * as a special notification event.
	 */
	public synchronized void notify ( int rowId ) {
		System.err.print( "{TARAN} Portal sent " );
		if ( DB_QUEUE == rowId )
			System.err.println( "DB_QUEUE signal." );
		if ( DB_UP == rowId )
			System.err.println( "DB_UP signal." );
		if ( DB_DOWN == rowId )
			System.err.println( "DB_DOWN signal." );
		if ( START == rowId ) {
			System.err.println( "START signal." );
			_alive = true;
		}
		if ( STOP == rowId ) {
			System.err.println( "STOP signal." );
			stopAllCrawlers();
			_alive = false;
			return;
		}
	}

	// CrawlListener impl

	/**
	 * Notification that the crawler was started.
	 * @param event a CrawlEvent instance that holds a detailed description 
	 * of the event
	 */
	public void started ( CrawlEvent event ) {
		
	}
	

	/**
	 * Notification that the crawler ran out of links to crawl
	 * @param event a CrawlEvent instance that holds a detailed description 
	 * of the event
	 */
	public void stopped ( CrawlEvent event ) {
		synchronized ( _crawlers ) {
			_crawlers.values().remove( event._crawler );
			if ( 0 == _crawlers.size() )
				_portal.set( this, Portal.DON_SPIDER );
		}
	}
	

	/**
	 * Notification that the crawler's state was cleared.
	 * @param event a CrawlEvent instance that holds a detailed description 
	 * of the event
	 */
	public void cleared ( CrawlEvent event ) {
	}
	

	/**
	 * Notification that the crawler timed out.
	 * @param event a CrawlEvent instance that holds a detailed description 
	 * of the event
	 */
	public void timedOut ( CrawlEvent event ) {
	}

	/**
	 * Notification that the crawler was paused.
	 * @param event a CrawlEvent instance that holds a detailed description 
	 * of the event
	 */
	public void paused ( CrawlEvent event ) {
	}

	// LinkListener impl
	
	/**
	 * Driver method for AuditRow / SessionRow pushes.
	 * The attached crawlers should send an event
	 * on each encountered link.
	 */
	public synchronized void crawled ( LinkEvent event ) {
		Link l = event._link;
		if ( LinkEvent.QUEUED == l.getStatus() ) {
			AuditRow a = new AuditRow( 
				new Object[] { null, null, null, l._url, null, 
				this, null, AuditRow.ST_RUN, null, null } );
			_portal.set( this, a );
			System.err.println( "{TARAN} link with labels: " + l.getObjectLabels() );
			System.err.println( "{TARAN} link with class " + l.getClass().getName() );
		}
		if ( LinkEvent.DOWNLOADED == l.getStatus() ) {
			if ( l.getPage().hasContent() && ! l.getPage().isImage() ) {
//				System.err.println( "{TARAN} pushed srow: " + l._url );
				SessionRow s = new SessionRow(
					new Object[] { null, null, l._url, l.getPage().getContent() } );
				_portal.set( this, s );
			}
			
			if ( Form.class == l.getClass() ) {
				System.err.println( "{TARAN} encountered form: " + l._url );
			}
		}
	}
	
} // class DbListener

