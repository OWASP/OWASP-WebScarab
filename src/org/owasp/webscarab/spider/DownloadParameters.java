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
 * Download parameters.  These parameters are limits on
 * how Page can download a Link.  A Crawler has a
 * default set of download parameters, but the defaults
 * can be overridden on individual links by calling
 * Link.setDownloadParameters().
 * <p>
 * DownloadParameters is an immutable class (like String).
 * "Changing" a parameter actually returns a new instance
 * of the class with only the specified parameter changed.
 * 
 * @since 0.poc
 * @version 0.poc<br />$Revision: 1.1 $ $Author: istr $
 * @author Robert C. Miller
 * @author Krishna Barat
 * @see <a href="http://www.cs.cmu.edu/~rcm/websphinx">WebSPHINX homepage</a>
 */
public class DownloadParameters 
	implements Cloneable, Serializable 
{
	/** number of background threads used by the crawler */
	private int maxThreads = 4;
	/** maximum page size in kilobytes (-1 for no maximum) */
	private int maxPageSize = 100;
	/** timeout for a single page, in seconds (-1 for no timeout) */
	private int downloadTimeout = 60;
	/** timeout for entire crawl in seconds (-1 for no timeout) */
	private int crawlTimeout = -1;
	/** obey crawling rules in robots.txt */
	private boolean obeyRobotExclusion = false;
	/** maximum number of simultaneous requests to a server (-1 for no maximum) */
	private int maxRequestsPerServer = 2;
	/** delay (in milliseconds) between starts of requests to same server (0 for no delay) */
	private int delay = 500;
	/** user is available to answer dialog boxes, e.g. for authentication */
	private boolean interactive = true;
	/** use cached pages to satisfy requests wherever possible */
	private boolean useCaches = false;
	/** accept header for HTTP request, or null to use default */
	private String acceptedMIMETypes = null;
	/** User-Agent header for HTTP request, or null to use default */
	private String userAgent = null;
	
	/** Make a DownloadParameters object with default settigns. */
	public DownloadParameters () {}

	/** Clone a DownloadParameters object. */
	public Object clone () {
		try {
			return super.clone();
		} 
		catch ( CloneNotSupportedException e ) {
			throw new RuntimeException( "Internal error: " + e );
		}
	}

	/** 
	 * Get maximum threads.
	 * @return maximum number of background threads used by crawler.
	 * Default is 4.
	 */
	public int getMaxThreads () {
		return maxThreads;
	}

	/** 
	 * Set maximum threads.
	 * @param maxthreads maximum number of background threads used by crawler
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeMaxThreads ( int maxthreads ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.maxThreads = maxthreads;
		return dp;
	}

	/** 
	 * Get maximum page size.  Pages larger than this limit are neither
	 * downloaded nor parsed.
	 * Default value is 100 (KB).
	 * @return maximum page size in kilobytes
	 */
	public int getMaxPageSize () {
		return maxPageSize;
	}

	/** 
	 * Change maximum page size.  Pages larger than this limit are treated as
	 * leaves in the crawl graph  -- neither downloaded nor parsed.
	 * @param maxPageSize maximum page size in kilobytes
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeMaxPageSize ( int maxPageSize ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.maxPageSize = maxPageSize;
		return dp;
	}

	/** 
	 * Get download timeout value.
	 * @return length of time (in seconds) that crawler will wait for a page to download
	 * before aborting it.
	 * timeout. Default is 60 seconds.
	 */
	public int getDownloadTimeout () {
		return downloadTimeout;
	}

	/** 
	 * Change download timeout value.
	 * @param timeout length of time (in seconds) to wait for a page to download
	 * Use a negative value to turn off timeout.
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeDownloadTimeout ( int timeout ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.downloadTimeout = timeout;
		return dp;
	}

	/** 
	 * Get timeout on entire crawl.
	 * @return maximum length of time (in seconds) that crawler will run
	 * before aborting.  Default is -1 (no limit).
	 */
	public int getCrawlTimeout () {
		return crawlTimeout;
	}

	/** 
	 * Change timeout value.
	 * @param timeout maximum length of time (in seconds) that crawler will run.
	 * Use a negative value to turn off timeout.
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeCrawlTimeout ( int timeout ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.crawlTimeout = timeout;
		return dp;
	}

	/** 
	 * Get obey-robot-exclusion flag.
	 * @return true iff the
	 * crawler checks robots.txt on the remote Web site
	 * before downloading a page.  Default is false.
	 */
	public boolean getObeyRobotExclusion () {
		return obeyRobotExclusion;
	}

	/** 
	 * Change obey-robot-exclusion flag.
	 * @param f   If true, then the
	 * crawler checks robots.txt on the remote Web site
	 * before downloading a page.
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeObeyRobotExclusion ( boolean f ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.obeyRobotExclusion = f;
		return dp;
	}

	/** 
	 * Get interactive flag.
	 * @return true if a user is available to respond to
	 * dialog boxes (for instance, to enter passwords for
	 * authentication).  Default is true.
	 */
	public boolean getInteractive () {
		return interactive;
	}

	/** 
	 * Change interactive flag.
	 * @param f true if a user is available to respond
	 * to dialog boxes
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeInteractive ( boolean f ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.interactive = f;
		return dp;
	}

	/** 
	 * Get use-caches flag.
	 * @return true if cached pages should be used whenever
	 * possible
	 */
	public boolean getUseCaches () {
		return useCaches;
	}

	/** 
	 * Change use-caches flag.
	 * @param f true if cached pages should be used whenever possible
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeUseCaches ( boolean f ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.useCaches = f;
		return dp;
	}

	/** 
	 * Get accepted MIME types.
	 * @return list of MIME types that can be handled by
	 * the crawler (which are passed as the Accept header
	 * in the HTTP request).
	 * Default is null.
	 */
	public String getAcceptedMIMETypes () {
		return acceptedMIMETypes;
	}

	/** 
	 * Change accepted MIME types.
	 * @param types list of MIME types that can be handled
	 * by the crawler.  Use null if the crawler can handle anything.
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeAcceptedMIMETypes ( String types ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.acceptedMIMETypes = types;
		return dp;
	}

	/** 
	 * Get User-agent header used in HTTP requests.
	 * @return user-agent field used in HTTP requests,
	 * or null if the Java library's default user-agent
	 * is used.  Default value is null (but for a Crawler,
	 * the default DownloadParameters has the Crawler's
	 * name as its default user-agent).
	 */
	public String getUserAgent () {
		return userAgent;
	}

	/** 
	 * Change User-agent field used in HTTP requests.
	 * @param userAgent user-agent field used in HTTP
	 * requests.  Pass null to use the Java library's default
	 * user-agent field.
	 * @return new DownloadParameters object with the specified parameter changed.
	 */
	public DownloadParameters changeUserAgent ( String userAgent ) {
		DownloadParameters dp = (DownloadParameters) clone();
		dp.userAgent = userAgent;
		return dp;
	}
}

