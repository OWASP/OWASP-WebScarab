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
 * NOTE: This file is an adaption of the WebSPHINX web _crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University
 * This package was released under the Library GPL but maintenance and
 * further development has been discontinued.
 * For a detailed information see http://www.cs.cmu.edu/~rcm/websphinx/
 * and read the README that can be found in this subpackage.
 */
package org.owasp.webscarab.spider.searchengine;

import org.owasp.webscarab.spider.EventLog;
import org.owasp.webscarab.spider.Crawler;
import org.owasp.webscarab.spider.MatchBox;
import org.owasp.webscarab.spider.Page;
import org.owasp.webscarab.spider.RegExp;
import org.owasp.webscarab.spider.TagExp;
import org.owasp.webscarab.spider.Region;
import org.owasp.webscarab.spider.Link;
import org.owasp.webscarab.spider.PatternMatcher;
import java.util.Vector;
import java.util.Iterator;
import java.util.NoSuchElementException;

/** 
 * Performs a searchengine search using a given searchengine class
 * that is specialized for one web search engine (lets say google).
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class Search 
	extends Crawler 
	implements Iterator 
{
	protected int _maxResults;
	protected int _walkedResults; // approximate number of results walked to
	protected Vector _results = new Vector(); // vector of SearchEngineResults
	protected int _nextResult = 0; // next result to be returned by the enumeration
	protected int _approxCount = -1; // (approximate) total number of results
	protected boolean _crawling = false;
	
	public Search () {
		this( Integer.MAX_VALUE );
	}
	
	public Search ( int maxResults ) {
		_maxResults = maxResults;
		setDepthFirst( false );
		setMaxDepth( Integer.MAX_VALUE );
		EventLog.monitor( this ); // FIX: debugging only
		}
	
	public Search ( SearchEngine engine, String keywords, int maxResults ) {
		this( maxResults );
		addQuery( engine, keywords );
		search();
	}
	
	public Search ( SearchEngine engine, String keywords ) {
		this( engine, keywords, Integer.MAX_VALUE );
	}

	public void addQuery ( SearchEngine engine, String keywords ) {
		addRoot( new Link( engine.makeQuery( keywords ) ) );
		addClassifier( engine );
		_walkedResults += engine.getResultsPerPage();
	}

	public void search () {
		_crawling = true;
		Thread thread = new Thread( this, "Search" );
		thread.setDaemon( true );
		thread.start();
	}

	public int count () {
		synchronized ( _results ) {
			// block until count is ready
			try {
				while ( _approxCount == -1 && _crawling ) 
					_results.wait();
			} 
			catch ( InterruptedException e ) {}
			return _approxCount;
		}
	}

	public boolean hasNext () {
		synchronized ( _results ) {
			try {
				while ( _nextResult >= _results.size() && _crawling ) 
					_results.wait();
			} 
			catch ( InterruptedException e ) {}
			return _nextResult < _results.size();
		}
	}

	public Object next () {
		return nextResult();
	}

	public void remove () {
		throw new UnsupportedOperationException( "not yet impld." );
	}

	public SearchEngineResult nextResult () {
		if ( !hasNext() )
			throw new NoSuchElementException();
		synchronized ( _results ) {
			SearchEngineResult result = (SearchEngineResult) _results.elementAt( _nextResult++ );
			if ( result.rank == 0 )
				result.rank = _nextResult;
			return result;
		}
	}

	public void run () {
		super.run();
		synchronized ( _results ) {
			if ( _approxCount == -1 )
				_approxCount = 0;
			_crawling = false;
			_results.notify();
		}
	}

	public void visit ( Page page ) {
		synchronized ( _results ) {
			if ( _approxCount == -1 )
				_approxCount = page.getNumericLabel( "searchengine.count", new Integer( 0 ) ).intValue();
			Region[] ser = page.getFields( "searchengine.results" );
			for ( int i = 0; i < ser.length; ++i ) {
				if ( _results.size() == _maxResults ) {
					stop();
					return ;
				}
				_results.addElement( ser[ i ] );
			}
			_results.notify();
		}
	}

	public boolean shouldVisit ( Link link ) {
		if ( _walkedResults >= _maxResults || !link.hasLabel( "searchengine.more-results" ) )
			return false;
		SearchEngine engine = (SearchEngine) link.getSource().getObjectLabel( "searchengine.source" );
		_walkedResults += engine.getResultsPerPage();
		return true;
	}

	public static void main ( String[] args )
		throws Exception
	{
		if ( args.length == 0 ) {
			System.err.println( "Search <search engine classname> [-max n]  <keywords>*" );
			return ;
		}
		SearchEngine engine = (SearchEngine) Class.forName( args[ 0 ] ).newInstance();
		int max = Integer.MAX_VALUE;
		int firstKeyword = 1;
		if ( args[ 1 ].equals( "-max" ) ) {
			max = Integer.parseInt( args[ 2 ] );
			firstKeyword = 3;
		}
		Search ms = new Search( max );
		ms.addQuery( engine, concat( args, firstKeyword ) );
		ms.search();
		while ( ms.hasNext() ) 
			System.out.println( ms.nextResult() );
	}

	static String concat ( String[] args, int start ) {
		StringBuffer buf = new StringBuffer();
		for ( int i = start; i < args.length; ++i ) {
			if ( buf.length() > 0 )
				buf.append( ' ' );
			buf.append( args[ i ] );
		}
		return buf.toString();
	}
}

