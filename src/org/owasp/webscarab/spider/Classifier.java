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

import java.io.Serializable;

/** 
 * Classifier interface.  A classifier is a helper object that annotates
 * pages and links with labels (using Page.setLabel() and Link.setLabel()).
 * When a page is retrieved by a crawler, it is passed to the classify()
 * method of every Classifier registered with the crawler.  Here are some
 * typical uses for classifiers:
 * <ul>
 * <li>classifying links into categories like child or parent
 * <li>classifying pages into categories like biology or computers;
 * <li>recognizing and parsing pages formatted in a particular style, such as
 * AltaVista, Yahoo, or latex2html (e.g., the search engine classifiers
 * in websphinx.searchengine)
 * <li>
 * </ul>
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 * @see DefaultClassifier
 */
public interface Classifier 
	extends Serializable
{
	

	/** 
	 * Classify a page.  Typically, the classifier calls page.setLabel() and
	 * page.setField() to mark up the page.  The classifier may also look
	 * through the page's links and call link.setLabel() to mark them up.
	 * @param page Page to classify
	 */
	void classify ( Page page );
	

	/** 
	 * Get priority of this classifier.  Lower priorities execute first.
	 * A classifier should also define a public constant <code>priority</code>
	 * so that classifiers that depend on it can compute their
	 * priorities statically.  For example, if your classifier
	 * depends on FooClassifier and BarClassifier, you might set your
	 * priority as:
	 * <pre>
	 * public static final long priority = Math.max( FooClassifier, BarClassifier ) + 1;
	 * public long getPriority () { return priority; }
	 * </pre>
	 * 
	 * @return priority of this classifier
	 */
	long getPriority ();
}

