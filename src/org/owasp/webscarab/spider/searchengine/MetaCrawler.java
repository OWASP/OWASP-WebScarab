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
package org.owasp.webscarab.spider.searchengine;

import org.owasp.webscarab.spider.MatchBox;
import org.owasp.webscarab.spider.Page;
import org.owasp.webscarab.spider.RegExp;
import org.owasp.webscarab.spider.TagExp;
import org.owasp.webscarab.spider.Region;
import org.owasp.webscarab.spider.Link;
import org.owasp.webscarab.spider.PatternMatcher;
import java.net.URL;
import java.net.URLEncoder;
import java.net.MalformedURLException;
import java.io.UnsupportedEncodingException;

/** 
 * <A href="http://www.metacrawler.com/">MetaCrawler</a> search engine.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class MetaCrawler 
	implements SearchEngine 
{
	static MatchBox patCount = new RegExp( "Collated Results: 1 to \\d+ of (\\d+) references" );
	static MatchBox patNoHits = new RegExp( "Your search did not produce any results" );
	static MatchBox patResult = new TagExp( "<dt><font color=#000000><b>(?{relevance})</b></font>" // relevance rating
	+ "(?{link}(?{title}<a>.*?</a>))" // title and main link
	+ "(?{description}<dt>.*?<font>)" // description
	);
	//static MatchBox patMoreLink = new RegExp (
	//    "<a href=\"http://\\w+.metacrawler.com/crawler\\?general.*?\">\\d+</a>"
	//);
	static MatchBox patMoreLink = new TagExp( "<a href=http://*.metacrawler.com/crawler\\?general*></a>" );

	/** 
	 * Classify a page.  Sets the following labels:
	 * <TABLE>
	 * <TR><TH>Name <TH>Type  <TH>Meaning
	 * <TR><TD>searchengine.source <TD>Page label <TD>MetaCrawler object that labeled the page
	 * <TR><TD>searchengine.count <TD>Page field <TD>Number of results on page
	 * <TR><TD>searchengine.results <TD>Page fields <TD>Array of results.  Each result region
	 * contains subfields: rank, title, description, and link.
	 * <TR><TD>searchengine.more-results <TD>Link label <TD>Link to a page containing more results.
	 * </TABLE>
	 */
	public void classify ( Page page ) {
		String title = page.getTitle();
		if ( title != null && title.startsWith( "Metacrawler query:" ) ) {
			page.setObjectLabel( "searchengine.source", this );
			Region count = patCount.oneMatch( page );
			if ( count != null )
				page.setField( "searchengine.count", count.getField( "0" ) );
			Region[] results = patResult.allMatches( page );
			SearchEngineResult[] ser = new SearchEngineResult[results.length];
			for ( int i = 0; i < results.length; ++i ) 
				ser[ i ] = new SearchEngineResult( results[ i ] );
			page.setFields( "searchengine.results", ser );
			PatternMatcher m = patMoreLink.match( page );
			while ( m.hasNext() ) {
				Link link = (Link) m.nextMatch();
				link.setLabel( "searchengine.more-results" );
				link.setLabel( "hyperlink" );
			}
		}
	}
	/** * Priority of this classifier. */
	public static final long PRIORITY = 0L;

	/** 
	 * Get priority of this classifier.
	 * @return priority.
	 */
	public long getPriority () {
		return PRIORITY;
	}

	/** 
	 * Make a query URL for MetaCrawler.
	 * @param keywords list of keywords, separated by spaces
	 * @return URL that submits the keywords to MetaCrawler.
	 */
	public URL makeQuery ( String keywords ) {
		try {
			return new URL( "http://www.metacrawler.com/crawler?general=" + URLEncoder.encode( keywords, 
				"UTF-8" ) + "&method=1&format=1&region=&rpp=20&timeout=15&hpe=10" );
		} 
		catch ( MalformedURLException e ) {
			throw new RuntimeException( "internal error" );
		} 
		catch ( UnsupportedEncodingException e ) {
			throw new RuntimeException( "fatal: UTF-8 encoding unsupported" );
		}
	}

	/** 
	 * Get number of results per page for this search engine.
	 * @return typical number of results per page
	 */
	public int getResultsPerPage () {
		return 20;
	}

	/** 
	 * Search MetaCrawler.
	 * @param keywords list of keywords, separated by spaces
	 * @return enumeration of SearchEngineResults returned by an MetaCrawler query constructed from the keywords.
	 */
	public static Search search ( String keywords ) {
		return new Search( new MetaCrawler(), keywords );
	}

	/** 
	 * Search MetaCrawler.
	 * @param keywords list of keywords, separated by spaces
	 * @param maxResults maximum number of results to return
	 * @return enumeration of SearchEngineResults returned by an MetaCrawler query constructed from the keywords.
	 * The enumeration yields at most maxResults objects.
	 */
	public static Search search ( String keywords, int maxResults ) {
		return new Search( new MetaCrawler(), keywords, maxResults );
	}
}

