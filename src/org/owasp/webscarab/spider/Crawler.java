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

import java.util.Vector;
import java.util.Iterator;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.net.URL;
import java.net.MalformedURLException;
import java.io.IOException;
import java.io.Serializable;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.owasp.util.StringUtil;
import org.owasp.webscarab.util.PriorityQueue;
import org.owasp.webscarab.util.Timer;

/** 
 * Web crawler.
 * <p>
 * To write a crawler, extend this class and override
 * shouldVisit () and visit() to create your own crawler.
 * <p>
 * To use a crawler:
 * <ol>
 * <li>Initialize the crawler by calling
 * setRoot() (or one of its variants) and setting other
 * crawl parameters.
 * <li>Register any classifiers you need with addClassifier().
 * <li>Connect event listeners to monitor the crawler,
 * such as websphinx.EventLog, websphinx.workbench.WebGraph,
 * or websphinx.workbench.Statistics.
 * <li>Call run() to start the crawler.
 * </ol>
 * A running crawler consists of a priority queue of
 * Links waiting to be visited and a set of threads
 * retrieving pages in parallel.  When a page is downloaded,
 * it is processed as follows:
 * <ol>
 * <li><b>classify()</b>: The page is passed to the classify() method of
 * every registered classifier, in increasing order of
 * their priority values.  Classifiers typically attach
 * informative labels to the page and its links, such as "homepage"
 * or "root page".
 * <li><b>visit()</b>: The page is passed to the crawler's
 * visit() method for user-defined processing.
 * <li><b>expand()</b>: The page is passed to the crawler's
 * expand() method to be expanded.  The default implementation
 * tests every unvisited hyperlink on the page with shouldVisit(),
 * and puts
 * each link approved by shouldVisit() into the crawling queue.
 * </ol>
 * By default, when expanding the links of a page, the crawler
 * only considers hyperlinks (not applets or inline images, for instance) that
 * point to Web pages (not mailto: links, for instance).  If you want
 * shouldVisit() to test every link on the page, use setLinkType(Crawler.ALL_LINKS).
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Crawler 
	implements Runnable, Serializable 
{
	private static final long serialVersionUID = -3757789861952010450L;
	/** 
	 * Specify WEB as the crawl domain to allow the crawler
	 * to visit any page on the World Wide Web.
	 */
	public static final String[] WEB = null;
	/** 
	 * Specify SERVER as the crawl domain to limit the crawler
	 * to visit only pages on the same Web server (hostname
	 * and port number) as the root link from which it started.
	 */
	public static final String[] SERVER = { "local" };
	/** 
	 * Specify SUBTREE as the crawl domain to limit the crawler
	 * to visit only pages which are descendants of the root link
	 * from which it started.
	 */
	public static final String[] SUBTREE = { "sibling", "descendent" };
	/** 
	 * Specify HYPERLINKS as the link type to allow the crawler
	 * to visit only hyperlinks (A, AREA, and FRAME tags which
	 * point to http:, ftp:, file:, or gopher: URLs).
	 */
	public static final String[] HYPERLINKS = { "hyperlink" };
	/** 
	 * Specify HYPERLINKS_AND_IMAGES as the link type to allow the crawler
	 * to visit only hyperlinks and inline images.
	 */
	public static final String[] HYPERLINKS_AND_IMAGES = { "hyperlink", "image" };
	/** 
	 * Specify ALL_LINKS as the link type to allow the crawler
	 * to visit any kind of link
	 */
	public static final String[] ALL_LINKS = null;
	// Crawler parameters
	/** name of the crawler */
	private String _name = getClass().getName();
	/** exists only when serializing crawler */
	private String[] _rootHrefs = null;
	/** domain to be crawled */
	private String[] _domain = WEB;
	/** flag whether operation should be done synchronously */
	private boolean _synchronous = false;
	/** flag whether to traverse the tree in depth (that is, until a leaf is reached) */
	private boolean _depthFirst = true;
	/** type of links to be followed */
	private String[] _type = HYPERLINKS;
	/** flag whether to skip already visited links */
	private boolean _ignoreVisitedLinks = true;
	/** maximum depth of tree traversal */
	private int _maxDepth = 5;
	/** download parameters */
	private DownloadParameters _dp = new DownloadParameters().changeUserAgent( _name );
	/** link classifiers */
	private Vector _classifiers = new Vector();
	/** link predicate */
	private LinkPredicate _linkPredicate;
	/** page predicate */
	private PagePredicate _pagePredicate;
	/** action to be performed encountering some link */
	private Action _action;
	// Transient state
	/** encountered "root" links */
	private transient Link[] _roots = null;
	/** crawled "root" links */
	private transient Link[] _crawledRoots = null;
	/** crawler state */
	private transient int _state = CrawlEvent.CLEARED;
	/** array of worms (worker threads) */
	private transient Worm[] _worms;
	/** background threads to fetch content of links */
	private transient PriorityQueue _fetchQueue;
	/** links waiting to be downloaded; all links that have been 
	 * expanded but not processed (used only if crawler is in
	 * synchronous mode)
	 */
	private transient PriorityQueue _crawlQueue;
	/** number of links tested by shouldVisit() */
	private transient int _numLinksTested;
	/** number of pages passed to visit() */
	private transient int _numPagesVisited;
	/** all links that have been expanded but not processed == crawlQueue.size () */
	private transient int _numPagesLeft;
	// FIXME: convert to immutable linked lists
	/** list of CrawlListeners */
	private transient Vector _crawlListeners;
	/** list of LinkListeners */
	private transient Vector _linkListeners;
	/** visited pages (a set of URLs) */
	private transient Hashtable _visitedPages;
	/** robot exclusion cache */
	private transient RobotExclusion _robotExclusion;
	
	/** Makes a new Crawler. */
	public Crawler () {
		addClassifier( new DefaultClassifier() );
		init();
	}

	/** Initializes the transient fields of the crawler. */
	private void init () {
		_state = CrawlEvent.CLEARED;
		_numLinksTested = 0;
		_numPagesVisited = 0;
		_numPagesLeft = 0;
		_worms = null;
		_crawlQueue = new PriorityQueue();
		_fetchQueue = new PriorityQueue();
		_crawlListeners = new Vector();
		_linkListeners = new Vector();
		_visitedPages = new Hashtable();
		_robotExclusion = new RobotExclusion( getName() );
	}

	/** Writes a Crawler to an output stream. */
	private void writeObject ( ObjectOutputStream out )
		throws IOException
	{
		if ( _roots != null ) {
			_rootHrefs = new String[_roots.length];
			for ( int i = 0; i < _roots.length; ++i ) 
				_rootHrefs[ i ] = _roots[ i ].getURL().toString();
		} else {
			_rootHrefs = null;
		}
		out.defaultWriteObject();
		_rootHrefs = null;
	}

	/** Reads a Crawler from an input stream. */
	private void readObject ( ObjectInputStream in )
		throws IOException, ClassNotFoundException
	{
		in.defaultReadObject();
		if ( _rootHrefs != null ) {
			_roots = new Link[_rootHrefs.length];
			for ( int i = 0; i < _rootHrefs.length; ++i ) 
				_roots[ i ] = new Link( _rootHrefs[ i ] );
		} else {
			_roots = null;
		}
		_domain = StringUtil.dflt( WEB, _domain );
		_domain = StringUtil.dflt( SERVER, _domain );
		_domain = StringUtil.dflt( SUBTREE, _domain );
		_type = StringUtil.dflt( HYPERLINKS, _type );
		_type = StringUtil.dflt( HYPERLINKS_AND_IMAGES, _type );
		_type = StringUtil.dflt( ALL_LINKS, _type );
		init();
		if ( null != _linkPredicate )
			_linkPredicate.connected( this );
		if ( null != _pagePredicate )
			_pagePredicate.connected( this );
		if ( null != _action )
			_action.connected( this );
	}

	/** 
	 * Start crawling.  Returns either when the crawl is done, or
	 * when pause() or stop() is called.  Because this method implements the
	 * java.lang.Runnable interface, a crawler can be run in the
	 * background thread.
	 */
	public void run () {
		_crawledRoots = _roots;
		if ( CrawlEvent.STOPPED == _state )
			clear();
		if ( CrawlEvent.CLEARED == _state && null != _crawledRoots ) {
			// give each root a default priority based on its position in the array
			long priority = 0;
			long increment = Long.MAX_VALUE / _crawledRoots.length;
			for ( int i = 0; i < _crawledRoots.length; ++i ) {
				_crawledRoots[ i ].setPriority( priority );
				priority += increment;
			}
			submit( _crawledRoots );
		}
		_state = CrawlEvent.STARTED;
		sendCrawlEvent( _state );
		synchronized ( _crawlQueue ) {
			Timer timer = new CrawlTimer( this );
			int timeout = _dp.getCrawlTimeout();
			if ( timeout > 0 )
				timer.set( timeout * 1000, false );
			int nWorms = Math.max( _dp.getMaxThreads(), 1 );
			_worms = new Worm[nWorms];
			for ( int i = 0; i < nWorms; ++i ) {
				_worms[ i ] = new Worm( this, i );
				_worms[ i ].start();
			}
			try {
				while ( CrawlEvent.STARTED == _state ) {
					if ( 0 == _numPagesLeft ) {
						// ran out of links to crawl
						_state = CrawlEvent.STOPPED;
						sendCrawlEvent( _state );
					} else {
						if ( _synchronous ) {
							// Synchronous mode.
							// Main thread calls process() on each link
							// in crawlQueue, in priority order.
							Link link = (Link) _crawlQueue.getMin();
							if ( LinkEvent.DOWNLOADED == link.getStatus() )
								process( link );
							else
								_crawlQueue.wait();
						} else {
							// Asynchronous crawling.
							// Main thread does nothing but wait, while
							// background threads call process().
							_crawlQueue.wait();
						}
					}
				}
			} 
			catch ( InterruptedException e ) {}
			timer.cancel();
			for ( int i = 0; i < _worms.length; ++i ) 
				_worms[ i ].die();
			if ( CrawlEvent.PAUSED == _state ) {
				// put partly-processed links back in fetchQueue
				synchronized ( _fetchQueue ) {
					for ( int i = 0; i < _worms.length; ++i ) 
						if ( _worms[ i ]._link != null )
							_fetchQueue.put( _worms[ i ]._link );
				}
			}
			_worms = null;
		}
	}

	/** 
	 * Initialize the crawler for a fresh crawl.  Clears the crawling queue
	 * and sets all crawling statistics to 0.  Stops the crawler
	 * if it is currently running.
	 */
	public void clear () {
		stop ();
		_numPagesVisited = 0;
		_numLinksTested = 0;
		clearVisited();
		if ( null != _crawledRoots )
			for ( int i = 0; i < _crawledRoots.length; ++i ) 
				_crawledRoots[ i ].disconnect();
		_crawledRoots = null;
		_state = CrawlEvent.CLEARED;
		sendCrawlEvent( _state );
	}

	/** 
	 * Pause the crawl in progress.  If the crawler is running, then
	 * it finishes processing the current page, then returns.  The queues remain as-is,
	 * so calling run() again will resume the crawl exactly where it left off.
	 * pause() can be called from any thread.
	 */
	public void pause () {
		if ( CrawlEvent.STARTED == _state ) {
			synchronized ( _crawlQueue ) {
				_state = CrawlEvent.PAUSED;
				_crawlQueue.notify();
			}
			sendCrawlEvent( _state );
		}
	}

	/** 
	 * Stop the crawl in progress.  If the crawler is running, then
	 * it finishes processing the current page, then returns.
	 * Empties the crawling queue.
	 */
	public void stop () {
	if ( CrawlEvent.STARTED == _state || CrawlEvent.PAUSED == _state ) {
		synchronized ( _crawlQueue ) {
			synchronized ( _fetchQueue ) {
				_state = CrawlEvent.STOPPED;
				_fetchQueue.clear();
				_crawlQueue.clear();
				_numPagesLeft = 0;
				_crawlQueue.notify();
			}
		}
		sendCrawlEvent( _state );
		}
	}
 
	/** 
	 * Timeout the crawl in progress.  Used internally by
	 * the CrawlTimer.
	 */
	void timedOut () {
		if ( CrawlEvent.STARTED == _state ) {
			synchronized ( _crawlQueue ) {
				synchronized ( _fetchQueue ) {
					_state = CrawlEvent.TIMED_OUT;
					_fetchQueue.clear();
					_crawlQueue.clear();
					_numPagesLeft = 0;
					_crawlQueue.notify();
				}
			}
			sendCrawlEvent( _state );
		}
	}

	/** 
	 * Get state of crawler.
	 * @return one of CrawlEvent.STARTED, CrawlEvent.PAUSED, STOPPED, CLEARED.
	 */
	public int getState () {
		return _state;
	}

	/** 
	 * Callback for visiting a page.  Default version does nothing.
	 * 
	 * @param page Page retrieved by the crawler
	 */
	public void visit ( Page page ) {}

	/** 
	 * Callback for testing whether a link should be traversed.
	 * Default version returns true for all links. Override this method
	 * for more interesting behavior.
	 * 
	 * @param l Link encountered by the crawler
	 * @return true if link should be followed, false if it should be ignored.
	 */
	public boolean shouldVisit ( Link l ) {
		return true;
	}

	/** 
	 * Expand the crawl from a page.  The default implementation of this
	 * method tests every link on the page using shouldVisit (), and
	 * submit()s the links that are approved.  A subclass may want to override
	 * this method if it's inconvenient to consider the links individually
	 * with shouldVisit().
	 * @param page Page to expand
	 */
	public void expand ( Page page ) {
		// examine each link on the page
		Link[] links = page.getLinks();
		if ( links != null && links.length > 0 ) {
			// give each link a default priority based on its page
			// and position on page
			long priority = (_depthFirst ? -_numPagesVisited : _numPagesVisited);
			long increment = Long.MAX_VALUE / links.length;
			for ( int i = 0; i < links.length; ++i ) {
				Link l = links[ i ];
				// set default download parameters
				l.setPriority( priority );
				priority += increment;
				l.setDownloadParameters( _dp );
				++_numLinksTested;
				if ( _ignoreVisitedLinks && visited( l ) )
					// FIX: use atomic test-and-set
					// FIX: set l.page somehow?
					sendLinkEvent( l, LinkEvent.ALREADY_VISITED );
				else 
				if ( !(( null==_type || l.hasAnyLabels( _type )) && ( null == _domain || l.hasAnyLabels( _domain )
					) && ( null == _linkPredicate || _linkPredicate.shouldVisit( l )) && shouldVisit( l )) )
					sendLinkEvent( l, LinkEvent.SKIPPED );
				else 
				if ( page.getDepth() >= _maxDepth )
					sendLinkEvent( l, LinkEvent.TOO_DEEP );
				else
					submit( l );
			}
		}
	}

	/* * Crawl statistics */
	/** 
	 * Get number of pages visited.
	 * @return number of pages passed to visit() so far in this crawl
	 */
	public int getPagesVisited () {
		return _numPagesVisited;
	}

	/** 
	 * Get number of links tested.
	 * @return number of links passed to shouldVisit() so far in this crawl
	 */
	public int getLinksTested () {
		return _numLinksTested;
	}

	/** 
	 * Get number of pages left to be visited.
	 * @return number of links approved by shouldVisit() but not yet visited
	 */
	public int getPagesLeft () {
		return _numPagesLeft;
	}

	/** 
	 * Get number of threads currently working.
	 * @return number of threads downloading pages
	 */
	public int getActiveThreads () {
		if ( null == _worms )
			return 0;
		Worm[] w = _worms;
		int n = 0;
		for ( int i = 0; i < w.length; ++i ) 
			if ( w[ i ] != null && w[ i ]._link != null )
				++n;
		return n;
	}

	/* * Crawler parameters */
	/** 
	 * Get human-readable name of crawler.  Default value is the
	 * class name, e.g., "Crawler".  Useful for identifying the crawler in a
	 * user interface; also used as the default User-agent for identifying
	 * the crawler to a remote Web server.  (The User-agent can be
	 * changed independently of the crawler name with setDownloadParameters().)
	 * @return human-readable name of crawler
	 */
	public String getName () {
		return _name;
	}

	/** 
	 * Set human-readable name of crawler.
	 * @param name new name for crawler
	 */
	public void setName ( String name ) {
		_name = name;
	}

	/** 
	 * Convert the crawler to a String.
	 * @return Human-readable name of crawler.
	 */
	public String toString () {
		return getName();
	}

	/** 
	 * Get starting points of crawl as an array of Link objects.
	 * @return array of Links from which crawler will start its next crawl.
	 */
	public Link[] getRoots () {
		if ( null == _roots )
			return new Link[0];
		Link[] result = new Link[_roots.length];
		System.arraycopy( _roots, 0, result, 0, _roots.length );
		return result;
	}

	/** 
	 * Get roots of last crawl.  May differ from getRoots()
	 * if new roots have been set.
	 * @return array of Links from which crawler started its last crawl,
	 * or null if the crawler was cleared.
	 */
	public Link[] getCrawledRoots () {
		if ( null == _crawledRoots )
			return null;
		Link[] result = new Link[_crawledRoots.length];
		System.arraycopy( _crawledRoots, 0, result, 0, _crawledRoots.length );
		return result;
	}

	/** 
	 * Get starting points of crawl as a String of newline-delimited URLs.
	 * @return URLs where crawler will start, separated by newlines.
	 */
	public String getRootHrefs () {
		StringBuffer buf = new StringBuffer();
		if ( null != _roots ) {
			for ( int i = 0; i < _roots.length; ++i ) {
				if ( buf.length() > 0 )
					buf.append( '\n' );
				buf.append( _roots[ i ].getURL().toExternalForm() );
			}
		}
		return buf.toString();
	}

	/** 
	 * Set starting points of crawl as a string of whitespace-delimited URLs.
	 * @param hrefs URLs of starting point, separated by space, \t, or \n
	 * @exception java.net.MalformedURLException if any of the URLs is invalid,
	 * leaving starting points unchanged
	 */
	public void setRootHrefs ( String hrefs )
		throws MalformedURLException
	{
		Vector v = new Vector();
		StringTokenizer tok = new StringTokenizer( hrefs );
		while ( tok.hasMoreElements() ) 
			v.addElement( new Link( tok.nextToken() ) );
		_roots = new Link[v.size()];
		v.copyInto( _roots );
	}

	/** 
	 * Set starting point of crawl as a single Link.
	 * @param link starting point
	 */
	public void setRoot ( Link link ) {
		_roots = new Link[1];
		_roots[ 0 ] = link;
	}

	/** 
	 * Set starting points of crawl as an array of Links.
	 * @param links starting points
	 */
	public void setRoots ( Link[] links ) {
		_roots = new Link[links.length];
		System.arraycopy( links, 0, _roots, 0, links.length );
	}

	/** 
	 * Add a root to the existing set of roots.
	 * @param link starting point to add
	 */
	public void addRoot ( Link link ) {
		if ( null == _roots ) {
			setRoot( link );
		} else {
			Link[] newroots = new Link[_roots.length + 1];
			System.arraycopy( _roots, 0, newroots, 0, _roots.length );
			newroots[ newroots.length - 1 ] = link;
			_roots = newroots;
		}
	}

	/** 
	 * Get crawl domain.  Default value is WEB.
	 * @return WEB, SERVER, or SUBTREE.
	 */
	public String[] getDomain () {
		return _domain;
	}

	/** 
	 * Set crawl domain.
	 * @param domain one of WEB, SERVER, or SUBTREE.
	 */
	public void setDomain ( String[] domain ) {
		_domain = domain;
	}

	/** 
	 * Get legal link types to crawl.  Default value is HYPERLINKS.
	 * @return HYPERLINKS, HYPERLINKS_AND_IMAGES, or ALL_LINKS.
	 */
	public String[] getLinkType () {
		return _type;
	}

	/** 
	 * Set legal link types to crawl.
	 * @param domain one of HYPERLINKS, HYPERLINKS_AND_IMAGES, or ALL_LINKS.
	 */
	public void setLinkType ( String[] type ) {
		_type = type;
	}

	/** 
	 * Get depth-first search flag.  Default value is true.
	 * @return true if search is depth-first, false if search is breadth-first.
	 */
	public boolean getDepthFirst () {
		return _depthFirst;
	}

	/** 
	 * Set depth-first search flag.  If neither depth-first nor breadth-first
	 * is desired, then override shouldVisit() to set a custom priority on
	 * each link.
	 * @param useDFS true if search should be depth-first, false if search should be breadth-first.
	 */
	public void setDepthFirst ( boolean useDFS ) {
		_depthFirst = useDFS;
	}

	/** 
	 * Get synchronous flag.  Default value is false.
	 * @return true if crawler must visit the pages in priority order; false if crawler can visit
	 * pages in any order.
	 */
	public boolean getSynchronous () {
		return _synchronous;
	}

	/** 
	 * Set ssynchronous flag.
	 * @param f true if crawler must visit the pages in priority order; false if crawler can visit
	 * pages in any order.
	 */
	public void setSynchronous ( boolean f ) {
		_synchronous = f;
	}

	/** 
	 * Get ignore-visited-links flag.  Default value is true.
	 * @return true if search skips links whose URLs have already been visited
	 * (or queued for visiting).
	 */
	public boolean getIgnoreVisitedLinks () {
		return _ignoreVisitedLinks;
	}

	/** 
	 * Set ignore-visited-links flag.
	 * @param f true if search skips links whose URLs have already been visited
	 * (or queued for visiting).
	 */
	public void setIgnoreVisitedLinks ( boolean f ) {
		_ignoreVisitedLinks = f;
	}

	/** 
	 * Get maximum depth.  Default value is 5.
	 * @return maximum depth of crawl, in hops from starting point.
	 */
	public int getMaxDepth () {
		return _maxDepth;
	}

	/** 
	 * Set maximum depth.
	 * @param maxDepth maximum depth of crawl, in hops from starting point
	 */
	public void setMaxDepth ( int maxDepth ) {
		_maxDepth = maxDepth;
	}

	/** 
	 * Get download parameters (such as number of threads, timeouts, maximum
	 * page size, etc.)
	 */
	public DownloadParameters getDownloadParameters () {
		return _dp;
	}

	/** 
	 * Set download parameters  (such as number of threads, timeouts, maximum
	 * page size, etc.)
	 * @param dp Download parameters
	 */
	public void setDownloadParameters ( DownloadParameters dp ) {
		_dp = dp;
	}

	/** 
	 * Set link predicate.  This is an alternative way to
	 * specify the links to walk.  If the link predicate is
	 * non-null, then only links that satisfy
	 * the link predicate AND shouldVisit() are crawled.
	 * @param pred Link predicate
	 */
	public void setLinkPredicate ( LinkPredicate predicate ) {
		if ( predicate == _linkPredicate || ( null != predicate && predicate.equals( _linkPredicate )) )
			return ;
		if ( null != _linkPredicate )
			_linkPredicate.disconnected( this );
		_linkPredicate = predicate;
		if ( null != _linkPredicate )
			_linkPredicate.connected( this );
	}

	/** 
	 * Get link predicate.
	 * @return current link predicate
	 */
	public LinkPredicate getLinkPredicate () {
		return _linkPredicate;
	}

	/** 
	 * Set page predicate.  This is a way to filter the pages
	 * passed to visit().  If the page predicate is
	 * non-null, then only pages that satisfy it are passed to visit().
	 * @param pred Page predicate
	 */
	public void setPagePredicate ( PagePredicate predicate ) {
		if ( predicate == _pagePredicate || ( null != predicate && predicate.equals( _pagePredicate )) )
			return ;
		if ( null != _pagePredicate )
			_pagePredicate.disconnected( this );
		_pagePredicate = predicate;
		if ( null != _pagePredicate )
			_pagePredicate.connected( this );
	}

	/** 
	 * Get page predicate.
	 * @return current page predicate
	 */
	public PagePredicate getPagePredicate () {
		return _pagePredicate;
	}

	/** 
	 * Set the action.  This is an alternative way to specify
	 * an action performed on every page.  If act is non-null,
	 * then every page passed to visit() is also passed to this
	 * action.
	 * @param action Action
	 */
	public void setAction ( Action action ) {
		if ( _action == action || (null != action && action.equals( _action )) )
			return ;
		if ( null != _action )
			_action.disconnected( this );
		_action = action;
		if ( null != _action )
			_action.connected( this );
	}

	/** 
	 * Get action.
	 * @return current action
	 */
	public Action getAction () {
		return _action;
	}

	/* 
	 * Link queue management
	 * 
	 */
	/** 
	 * Puts a link into the crawling queue.  If the crawler is running, the
	 * link will eventually be retrieved and passed to visit().
	 * @param link Link to put in queue
	 */
	public void submit ( Link link ) {
		markVisited( link ); // FIX: need atomic test-and-set of visited flag
		synchronized ( _crawlQueue ) {
			synchronized ( _fetchQueue ) {
				_crawlQueue.put( link );
				++_numPagesLeft;
				_fetchQueue.put( link );
				_fetchQueue.notifyAll(); // wake up worms
			}
		}
		sendLinkEvent( link, LinkEvent.QUEUED );
	}

	/** 
	 * Submit an array of Links for crawling.  If the crawler is running,
	 * these links will eventually be retrieved and passed to visit().
	 * @param links Links to put in queue
	 */
	public void submit ( Link[] links ) {
		for ( int i = 0; i < links.length; ++i ) 
			submit( links[ i ] );
	}

	/** 
	 * Enumerate crawling queue.
	 * @return an enumeration of Link objects which are waiting to be visited.
	 */
	public Iterator enumerateQueue () {
		// FIXME: enumerate in priority order
		return _crawlQueue.elements();
	}

	/* 
	 * Classifiers
	 * 
	 */
	/** 
	 * Adds a classifier to this crawler.  If the
	 * classifier is already found in the set, does nothing.
	 * @param c a classifier
	 */
	public void addClassifier ( Classifier c ) {
		if ( !_classifiers.contains( c ) ) {
			float cpriority = c.getPriority();
			for ( int i = 0; i < _classifiers.size(); ++i ) {
				Classifier d = (Classifier) _classifiers.elementAt( i );
				if ( cpriority < d.getPriority() ) {
					_classifiers.insertElementAt( c, i );
					return;
				}
			}
			_classifiers.addElement( c );
		}
	}

	/** 
	 * Removes a classifier from the set of classifiers.
	 * If c is not found in the set, does nothing.
	 * 
	 * @param c a classifier
	 */
	public void removeClassifier ( Classifier c ) {
		_classifiers.removeElement( c );
	}

	/** * Clears the set of classifiers. */
	public void removeAllClassifiers () {
		_classifiers.removeAllElements();
	}

	/** 
	 * Enumerates the set of classifiers.
	 * 
	 * @return An enumeration of the classifiers.
	 */
	public Iterator classifiersIterator () {
		return _classifiers.iterator();
	}

	/** 
	 * Get the set of classifiers
	 * 
	 * @return An array containing the registered classifiers.
	 */
	public Classifier[] getClassifiers () {
		Classifier[] c = new Classifier[_classifiers.size()];
		_classifiers.copyInto( c );
		return c;
	}

	/* 
	 * Event listeners
	 * 
	 */
	/** 
	 * Adds a listener to the set of CrawlListeners for this crawler.
	 * If the listener is already found in the set, does nothing.
	 * 
	 * @param listen a listener
	 */
	public void addCrawlListener ( CrawlListener listen ) {
		if ( !_crawlListeners.contains( listen ) )
			_crawlListeners.addElement( listen );
	}

	/** 
	 * Removes a listener from the set of CrawlListeners.  If it is not found in the set,
	 * does nothing.
	 * 
	 * @param listen a listener
	 */
	public void removeCrawlListener ( CrawlListener listen ) {
		_crawlListeners.removeElement( listen );
	}
	
	/** 
	 * Adds a listener to the set of LinkListeners for this crawler.
	 * If the listener is already found in the set, does nothing.
	 * 
	 * @param listen a listener
	 */
	public void addLinkListener ( LinkListener listen ) {
		if ( !_linkListeners.contains( listen ) )
			_linkListeners.addElement( listen );
	}

	/** 
	 * Removes a listener from the set of LinkListeners.  If it is not found in the set,
	 * does nothing.
	 * 
	 * @param listen a listener
	 */
	public void removeLinkListener ( LinkListener listen ) {
		_linkListeners.removeElement( listen );
	}

	/** 
	 * Send a CrawlEvent to all CrawlListeners registered with this crawler.
	 * @param id Event id
	 */
	protected void sendCrawlEvent ( int id ) {
		CrawlEvent evt = new CrawlEvent( this, id );
		for ( int j = 0,  len = _crawlListeners.size(); j < len; ++j ) {
			CrawlListener listen = (CrawlListener) _crawlListeners.elementAt( j );
			switch ( id ) {
				case CrawlEvent.STARTED:
					listen.started( evt );
					break;
				case CrawlEvent.STOPPED:
					listen.stopped( evt );
					break;
				case CrawlEvent.CLEARED:
					listen.cleared( evt );
					break;
				case CrawlEvent.TIMED_OUT:
					listen.timedOut( evt );
					break;
				case CrawlEvent.PAUSED:
					listen.paused( evt );
					break;
			}
		}
	}

	/** 
	 * Send a LinkEvent to all LinkListeners registered with this crawler.
	 * @param l Link related to event
	 * @param id Event id
	 */
	protected void sendLinkEvent ( Link l, int id ) {
		LinkEvent evt = new LinkEvent( this, id, l );
		l.setStatus( id );
		for ( int j = 0,  len = _linkListeners.size(); j < len; ++j ) {
			LinkListener listen = (LinkListener) _linkListeners.elementAt( j );
			listen.crawled( evt );
		}
	}

	/** 
	 * Send an exceptional LinkEvent to all LinkListeners registered with this crawler.
	 * @param l Link related to event
	 * @param id Event id
	 * @param exception Exception associated with event
	 */
	protected void sendLinkEvent ( Link l, int id, Throwable exception ) {
		LinkEvent evt = new LinkEvent( this, id, l, exception );
		l.setStatus( id );
		l.setLabel( "exception", exception.toString() );
		for ( int j = 0,  len = _linkListeners.size(); j < len; ++j ) {
			LinkListener listen = (LinkListener) _linkListeners.elementAt( j );
			listen.crawled( evt );
		}
	}

	/* 
	 * Visited pages table
	 * 
	 */
	/** 
	 * Test whether the page corresponding to a link has been visited
	 * (or queued for visiting).
	 * @param link  Link to test
	 * @return true if link has been passed to walk() during this crawl
	 */
	public boolean visited ( Link link ) {
		return _visitedPages.containsKey( link.getPageURL().toString() );
	}

	/** 
	 * Register that a link has been visited.
	 * @param link  Link that has been visited
	 */
	protected void markVisited ( Link link ) {
		_visitedPages.put( link.getPageURL().toString(), this );
	}

	/** Clears the set of visited links. */
	protected void clearVisited () {
		_visitedPages.clear();
	}

	/* 
	 * Fetch loop
	 * 
	 */
	void fetch ( Worm w ) {
		Timer timer = new WormTimer( w );
		while ( !w._dead ) {
			//System.err.println (w + ": fetching a link");
			// pull the highest-priority link from the fetch queue
			synchronized ( _fetchQueue ) {
				while ( !w._dead && (w._link = (Link) _fetchQueue.deleteMin()) == null ) {
					try {
						_fetchQueue.wait();
					} 
					catch ( InterruptedException e ) {}
				}
			}
			if ( w._dead )
				return ;
			//System.err.println (w + ": processing " + w.link.toDescription());
			try {
				// download the link to get a page
				DownloadParameters dp;
				Page page;
				dp = w._link.getDownloadParameters();
				if ( null == dp )
					dp = _dp;
				int timeout = dp.getDownloadTimeout();
				sendLinkEvent( w._link, LinkEvent.RETRIEVING );
				try {
					if ( timeout > 0 )
						timer.set( timeout * 1000, false );
					if ( dp.getObeyRobotExclusion() && _robotExclusion.disallowed( w._link.getURL() ) )
						throw new IOException( "disallowed by Robot Exclusion Standard (robots.txt)" );
					page = new Page( w._link, new HTMLParser( dp ) );
				} 
				finally {
					timer.cancel();
				}
				if ( w._dead )
					return ;
				sendLinkEvent( w._link, LinkEvent.DOWNLOADED );
				if ( _synchronous ) {
					// Synchronous mode.
					// Main thread will call process() when
					// this link's turn arrives (in priority order).
					// Wake up the main thread.
					synchronized ( _crawlQueue ) {
						_crawlQueue.notify();
					}
				} else {
					// Asynchronous mode.
					// Each worm calls process() on its link.
					process( w._link );
				}
				w._link = null;
			// loop around and fetch another link
			} 
			catch ( ThreadDeath e ) {
				throw e; // have to continue dying
				} 
			catch ( Throwable e ) {
				// Some other exception occurred, either during the page fetch
				// or in some user code.  Mark up the link with the error.
				if ( w._dead )
					return ;
				sendLinkEvent( w._link, LinkEvent.ERROR, e );
				synchronized ( _crawlQueue ) {
					_crawlQueue.delete( w._link );
					--_numPagesLeft;
					w._link = null;
					_crawlQueue.notify();
				}
			}
		}
	}

	void process ( Link link ) {
		Page page = link.getPage();
		// classify the page
		for ( int j = 0,  len = _classifiers.size(); j < len; ++j ) {
			Classifier cl = (Classifier) _classifiers.elementAt( j );
			cl.classify( page );
		}
		// invoke callbacks on the page
		++_numPagesVisited;
		if ( null == _pagePredicate || _pagePredicate.shouldActOn( page ) ) {
			if ( null != _action )
				_action.visit( page );
			visit( page );
		}
		expand( page );
		// send out the event
		sendLinkEvent( link, LinkEvent.VISITED );
		// discard link
		synchronized ( _crawlQueue ) {
			_crawlQueue.delete( link );
			--_numPagesLeft;
			_crawlQueue.notify();
		}
	}

	void fetchTimedOut ( Worm w, int interval ) {
		if ( w._dead )
			return ;
		w.die();
		sendLinkEvent( w._link, LinkEvent.ERROR, new IOException( "Timeout after " + interval + " seconds"
			 ) );
		synchronized ( _crawlQueue ) {
			_crawlQueue.delete( w._link );
			--_numPagesLeft;
			_worms[ w._i ] = new Worm( this, w._i );
			_worms[ w._i ].start();
			_crawlQueue.notify();
		}
	}

	// FIX: more error checking here
	public static void main ( String[] args )
		throws Exception
	{
		ObjectInputStream in = new ObjectInputStream( new FileInputStream( args[ 0 ] ) );
		Crawler loadedCrawler = (Crawler) in.readObject();
		in.close();
		EventLog.monitor( loadedCrawler );
		loadedCrawler.run();
	}
}

