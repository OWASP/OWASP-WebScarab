/*
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University 
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software 
 * Foundation, version 2.
 *
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.spider.workbench;

import websphinx.*;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.MalformedURLException;

public class MirrorAction implements Action, CrawlListener {
    String directory;
    boolean useBrowser;

    transient File dir;
    transient Mirror mirror;

    public MirrorAction (String directory, boolean useBrowser) {
        this.directory = directory;
        this.useBrowser = useBrowser;
    }

    public boolean equals (Object object) {
        if (! (object instanceof MirrorAction))
            return false;
        MirrorAction a = (MirrorAction)object;
        return same (a.directory, directory)
            && a.useBrowser == useBrowser;
    }    

    private boolean same (String s1, String s2) {
        if (s1 == null || s2 == null)
            return s1 == s2;
        else
            return s1.equals (s2);
    }

    public String getDirectory () {
        return directory;
    }

    public boolean getUseBrowser () {
        return useBrowser;
    }

    private void showit () {
        Browser browser = Context.getBrowser();
        if (browser != null)
            try {
                browser.show (Link.FileToURL (dir));
            } catch (MalformedURLException e) {}
    }

    public synchronized void visit (Page page) {
        try {
            mirror.writePage (page);
        } catch (IOException e) {
            throw new RuntimeException (e.toString());
        }
    }

    public void connected (Crawler crawler) {
        crawler.addCrawlListener (this);
    }

    public void disconnected (Crawler crawler) {
        crawler.removeCrawlListener (this);
    }

    /**
     * Notify that the crawler started.
     */
    public void started (CrawlEvent event){
        if (mirror == null) {
            try {
                dir = (directory != null)
                  ? new File (directory)
                  : SecurityPolicy.getPolicy().makeTemporaryFile ("mirror", "");
                mirror = new Mirror (dir.toString());
                
                Crawler crawler = event.getCrawler ();
                Link[] roots = crawler.getRoots ();
                for (int i=0; i<roots.length; ++i)
                    mirror.mapDir (roots[i].getURL(), dir.toString());
            } catch (IOException e) {
                System.err.println (e); // FIX: use GUI when available
            }        
        }
    }

    /**
     * Notify that the crawler ran out of links to crawl
     */
    public void stopped (CrawlEvent event){
        try {
            if (mirror != null) {
                mirror.close ();
                mirror = null;
                
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

    /**
     * Notify that the crawler's state was cleared.
     */
    public void cleared (CrawlEvent event){
        try {
            if (mirror != null) {
                mirror.close ();
                mirror = null;
                
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

    /**
     * Notify that the crawler timed out.
     */
    public void timedOut (CrawlEvent event){
        try {
            if (mirror != null) {
                mirror.close ();
                mirror = null;
                
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

    /**
     * Notify that the crawler is paused.
     */
    public void paused (CrawlEvent event){
        try {
            if (mirror != null) {
                mirror.rewrite ();
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

}

