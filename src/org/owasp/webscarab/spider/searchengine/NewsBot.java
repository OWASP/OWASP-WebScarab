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
 * <A href="http://www.newbot.com/">NewsBot</a> search engine.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class NewsBot 
	implements SearchEngine 
{
	static MatchBox patTitle = new RegExp( "^" );
	static MatchBox patCount = new RegExp( "Returned <B>(\\d+)</b> results" );
	static MatchBox patNoHits = new RegExp( "Sorry -- your search yielded no results" );
	// FIX: works only for Netscape
	static MatchBox patResult = new TagExp( "<font>" + "(?{link}<A>(?{title})</A>)" + "</font>"
		+ "<br>" + "<font></font>(?{description})<br>" + "<font><b></b></font><p>" );
	static MatchBox patMoreLink = new TagExp( "<input type=image name=act.next>" );

	/** 
	 * Classify a page.  Sets the following labels:
	 * <TABLE>
	 * <TR><TH>Name <TH>Type  <TH>Meaning
	 * <TR><TD>searchengine.source <TD>Page label <TD>NewsBot object that labeled this page
	 * <TR><TD>searchengine.count <TD>Page field <TD>Number of results on page
	 * <TR><TD>searchengine.results <TD>Page fields <TD>Array of results.  Each result region
	 * contains subfields: rank, title, description, and link.
	 * <TR><TD>searchengine.more-results <TD>Link label <TD>Link to a page containing more results.
	 * </TABLE>
	 */
	public void classify ( Page page ) {
		String title = page.getTitle();
		if ( title != null && title.startsWith( "HotBot results:" ) ) {
			page.setObjectLabel( "searchengine.source", this );
			Region count = patCount.oneMatch( page );
			if ( count != null )
				page.setField( "searchengine.count", count.getField( "0" ) );
			Region[] results = patResult.allMatches( page );
			SearchEngineResult[] ser = new SearchEngineResult[results.length];
			for ( int i = 0; i < results.length; ++i ) {
				ser[ i ] = new SearchEngineResult( results[ i ] );
			//System.out.println (ser[i]);
			}
			page.setFields( "searchengine.results", ser );
			PatternMatcher m = patMoreLink.match( page );
			while ( m.hasNext() ) {
				Link link = (Link) m.nextMatch();
				link.setLabel( "searchengine.more-results" );
				link.setLabel( "hyperlink" );
			}
		} else {
			System.err.println( "not a NewsBot page" );
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
	 * Make a query URL for NewsBot.
	 * @param keywords list of keywords, separated by spaces
	 * @return URL that submits the keywords to NewsBot.
	 */
	public URL makeQuery ( String keywords ) {
		try {
			java.util.StringTokenizer tok = new java.util.StringTokenizer( keywords );
			StringBuffer output = new StringBuffer();
			while ( tok.hasMoreElements() ) {
				String kw = tok.nextToken();
				if ( output.length() > 0 )
					output.append( " or " );
				output.append( kw );
			}
			return new URL( "http://engine.newbot.com/newbot/server/query.fpl?client_id=0sQaJNoAahXc&output=hotbot4&logad=1&client_sw=html&client_vr=0.9&client_last_updated=ignore&T0=hotbot&S0=date&P0=&F0=24&Q0=" + URLEncoder.encode( output.toString(), 
				"UTF-8" ) + "&max_results=50&S0=rank&Search.x=55&Search.y=4" );
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
		return 10;
	}

	/** 
	 * Search NewsBot.
	 * @param keywords list of keywords, separated by spaces
	 * @return enumeration of SearchEngineResults returned by a NewsBot query constructed from the keywords.
	 */
	public static Search search ( String keywords ) {
		return new Search( new NewsBot(), keywords );
	}

	/** 
	 * Search NewsBot.
	 * @param keywords list of keywords, separated by spaces
	 * @param maxResults maximum number of results to return
	 * @return enumeration of SearchEngineResults returned by an NewsBot query constructed from the keywords.
	 * The enumeration yields at most maxResults objects.
	 */
	public static Search search ( String keywords, int maxResults ) {
		return new Search( new NewsBot(), keywords, maxResults );
	}
}

