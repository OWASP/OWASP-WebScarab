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

/** 
 * Result returned by a search engine query, identifying a Web page that matches the query.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class SearchEngineResult 
	extends Region 
{
	/** 
	 * Relevancy rank of page in search engine's ordering.  In other words, rank=1
	 * is the first result the search engine returned.  If search engine
	 * results are not explicitly numbered, then rank may be 0.
	 */
	public int rank = 0;
	/** 
	 * Relevancy score of page, by search engine's scale.  If search engine
	 * does not provide a score, the score defaults to 0.0.
	 * 
	 */
	public double score = 0.0;
	/** * Title of page as reported by search engine, or null if not provided */
	public String title;
	/** 
	 * Short description of page as reported by search engine.  Typically the first few words
	 * of the page.  If not provided, description is null.
	 */
	public String description;
	/** * Link to the actual page. */
	public Link link;
	/** * Search engine that produced this hit. */
	public SearchEngine searchengine;
	
	/** 
	 * Make a SearchEngineResult.
	 * @param result Region of a search engine's results page.  Should be annotated with rank, title,
	 * description, and link fields.
	 */
	public SearchEngineResult ( Region result ) {
		super( result );
		rank = result.getNumericLabel( "rank", new Integer( 0 ) ).intValue();
		score = result.getNumericLabel( "score", new Double( 0 ) ).doubleValue();
		title = result.getLabel( "title" );
		description = result.getLabel( "description" );
		try {
			link = (Link) result.getField( "link" );
		} 
		catch ( ClassCastException e ) {}
		searchengine = (SearchEngine) result.getSource().getObjectLabel( "searchengine.source" );
	}

	public String toString () {
		return rank + ". " + title + " [" + (link != null ? link.getURL().toString() : "(null)")
			+ "]" + " " + score + "\n" + "    " + description;
	}
}

