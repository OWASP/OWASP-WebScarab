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
import java.awt.*;
import java.text.NumberFormat;
import websphinx.util.Constrain;
import websphinx.util.Mem;
import websphinx.util.ClosableFrame;
import websphinx.util.BorderPanel;

public class Statistics extends Panel implements CrawlListener, Runnable {

    Crawler crawler;
    Thread thread;
    boolean running = false;

    static final int PAGES_PER_SEC_DECIMAL_PLACES = 1;
    static final NumberFormat fmtPagesPerSec = NumberFormat.getInstance ();
    static {
        fmtPagesPerSec.setMinimumFractionDigits (PAGES_PER_SEC_DECIMAL_PLACES);
        fmtPagesPerSec.setMaximumFractionDigits (PAGES_PER_SEC_DECIMAL_PLACES);
    }

    String runningTime;
    String activeThreads;
    String linksTested;
    String pagesVisited;
    String pagesPerSec;
    String pagesLeft;
    String memoryUsed;
    String memoryMaxUsed;

    Button refreshButton;

    long msecTotal;
    long timeLastUpdate = -1;
    long kbMaxUsed;

    public Statistics () {
        setLayout (null);
        add (refreshButton = new Button ("Refresh"));
        update ();
        measureFields (); // to initialize minSize
    }


    Image offscreen;     // offscreen drawing area
    Dimension offSize;   // size of offscreen buffer
    Graphics offg;       // drawonable associated with offscreen buffer
    FontMetrics fm;      // font metrics for offscreen buffer

    Dimension minSize = new Dimension ();
    
    public synchronized void layout () {
        Dimension d = refreshButton.preferredSize();
        int x = 0;
        int y = minSize.height;
        int w = d.width;
        int h = d.height;
        refreshButton.reshape (x, y, w, h);
    }

    public Dimension minimumSize () {
        Dimension d = new Dimension (minSize);
        d.height += refreshButton.preferredSize().height;
        return d;
    }

    public Dimension preferredSize () {
        return minimumSize ();
    }

    public synchronized void update (Graphics g) {
        // don't clear window with background color first
        paint (g);
    }

    void createOffscreenArea (Dimension d) {
        offSize = new Dimension (d.width  > 0 ? d.width : 1,
                                 d.height  > 0 ? d.height : 1);
        offscreen = createImage (offSize.width, offSize.height);
        offg = offscreen.getGraphics ();
        offg.setFont (getFont ());
        fm = offg.getFontMetrics ();
    }

    final static int GUTTER = 5;

    int drawField (Graphics g, int y, String caption, String value) {
        int cW = fm.stringWidth (caption);
        int vW = fm.stringWidth (value);
        minSize.width = Math.max (minSize.width, cW + vW + 10);

        y += fm.getAscent ();
        g.drawString (caption, 0, y);
        g.drawString (value, offSize.width - fm.stringWidth (value), y);
        return fm.getHeight ();
    }

    void drawFields (Graphics g) {
        int y = 0;
        int gutter = GUTTER;
        //+ Math.max (0, offSize.height - minSize.height) / 8;

        y += gutter;
        y += drawField (offg, y, "Running time:", runningTime);
        y += drawField (offg, y, "Active threads:", activeThreads);
        y += gutter*2;
        y += drawField (offg, y, "Links tested:", linksTested);
        y += drawField (offg, y, "Links in queue:", pagesLeft);
        y += gutter*2;
        y += drawField (offg, y, "Pages visited:", pagesVisited);
        y += drawField (offg, y, "Pages/sec:", pagesPerSec);
        y += gutter*2;
        y += drawField (offg, y, "Memory in use:", memoryUsed);
        y += drawField (offg, y, "Max memory used:", memoryMaxUsed);
        y += gutter;

        minSize.height = y;
    }

    int measureField (FontMetrics fm, String caption, String value) {
        int cW = fm.stringWidth (caption);
        int vW = fm.stringWidth ("00000000");
        minSize.width = Math.max (minSize.width, cW + vW + 10);
        return fm.getHeight ();
    }

    void measureFields () {
        Font font = getFont ();
        if (font == null)
            font = new Font ("Helvetica", Font.PLAIN, 12);
        FontMetrics fm = Toolkit.getDefaultToolkit().getFontMetrics (font);
        minSize = new Dimension ();

        int y = 0;

        y += GUTTER;
        y += measureField (fm, "Running time:", runningTime);
        y += measureField (fm, "Active threads:", activeThreads);
        y += GUTTER*2;
        y += measureField (fm, "Links tested:", linksTested);
        y += measureField (fm, "Links in queue:", pagesLeft);
        y += GUTTER*2;
        y += measureField (fm, "Pages visited:", pagesVisited);
        y += measureField (fm, "Pages/sec:", pagesPerSec);
        y += GUTTER*2;
        y += measureField (fm, "Memory in use:", memoryUsed);
        y += measureField (fm, "Max memory used:", memoryMaxUsed);
        y += GUTTER;

        minSize.height = y;
    }

    Dimension cached;

    public synchronized void paint (Graphics g) {
        Dimension d = size ();
        if (cached == null
            || d.width != cached.width
            || d.height != cached.height) {
            g.setColor (getBackground ());
            g.fillRect (0, 0, d.width, d.height);
            cached = d;
        }

        if (offscreen == null)
            createOffscreenArea (minSize);

        // erase background
        offg.setColor (getBackground ());
        offg.fillRect (0, 0, offSize.width, offSize.height);
        
        // draw statistics
        offg.setColor (getForeground ());
        drawFields (offg);
            
        // copy to screen
        g.drawImage (offscreen, 0, 0, null);
    }

    public boolean handleEvent (Event event) {
        if (event.target == refreshButton && event.id == Event.ACTION_EVENT) {
            Mem.verbosegc ();
            update ();
        }
        else
            return super.handleEvent (event);
        return true;
    }
            

    /**
     * Reset statistics (primarily the running time, since all other
     * statistics are computed directly from the crawler's state).  
     * If listening to a crawler, this method is called automatically 
     * when the crawler is cleared.
     */
    public synchronized void clear () {
        msecTotal = 0;
        timeLastUpdate = -1;
        update ();
    }

    /**
     * Compute the latest statistics.  Called automatically by
     * a background thread when the crawler is running.
     */
    public synchronized void update () {
        long now = System.currentTimeMillis ();
        if (running) {
            if (timeLastUpdate != -1)
                msecTotal += (now - timeLastUpdate);
            timeLastUpdate = now;
        }

        int pV, lT, pL, nThreads;

        if (crawler != null) {
            lT = crawler.getLinksTested ();
            pV = crawler.getPagesVisited ();
            pL = crawler.getPagesLeft ();
            nThreads = crawler.getActiveThreads ();
        }
        else {
            lT = 0;
            pV = 0;
            pL = 0;
            nThreads = 0;
        }

        long kbUsed = Mem.used () / 1024;
        kbMaxUsed = Math.max (kbMaxUsed, kbUsed);

        double pps = msecTotal > 0
            ? (double)pV * 1000 / msecTotal
            : 0.0;
            
            
        runningTime = formatTime (msecTotal);
        activeThreads = String.valueOf (nThreads);
        linksTested = String.valueOf (lT);
        pagesVisited = String.valueOf (pV);
        pagesLeft = String.valueOf (pL);
        pagesPerSec = formatPagesPerSec (pps);
        memoryUsed = kbUsed + " KB";
        memoryMaxUsed = kbMaxUsed + " KB";

        // paint the window NOW
        Graphics g = getGraphics ();
        if (g != null)
            update (g);
    }

    static String formatTime (long time) {
        int h, m, s, d;
        s = (int) (time/1000);
        m = s / 60; s %= 60;
        h = m / 60; m %= 60;
        d = h / 24; h %= 24;
        return formatTime (d, h, m, s);
    }

    static String formatTime (int d, int h, int m, int s) {
        return
            (d > 0 ? d + "d " : "")
            + (h < 10 ? "0" : "") + h
            + ":" + (m < 10 ? "0" : "") + m
            + ":" + (s < 10 ? "0" : "") + s;
    }
    
    static String formatPagesPerSec (double x) {
        return fmtPagesPerSec.format (x);
    }

    /**
     * Start the background thread to update the display.  If listening
     * to a crawler, this method is called automatically when the  
     * crawler starts.
     */
    public synchronized void start () {
        running = true;
        thread = new Thread (this, "Statistics");
        thread.setDaemon (true);
        thread.setPriority (Thread.MIN_PRIORITY);
        thread.start ();
    }

    /**
     * Stop the background thread that updates the display.  If listening
     * to a crawler, this method is called automatically when the  
     * crawler stops.
     */
    public synchronized void stop () {
        running = false;
        thread = null;
        timeLastUpdate = -1;
    }

    /**
     * Background thread.  Clients shouldn't call this.
     */
    public void run () {
        while (true) {
            update ();

            if (!running)
                break;

            try {
                Thread.sleep (500);
            } catch (InterruptedException e) {}
        }
    }

    /**
     * Notify that the crawler started.
     */
    public void started (CrawlEvent event) {
        crawler = event.getCrawler ();
        start ();
    }

    /**
     * Notify that the crawler ran out of links to crawl
     */
    public synchronized void stopped (CrawlEvent event) {
        if (running)
            stop ();
    }

    /**
     * Notify that the crawler's state was cleared.
     */
    public void cleared (CrawlEvent event) {
        clear ();
    }

    /**
     * Notify that the crawler timed out.
     */
    public void timedOut (CrawlEvent event) {
        stop ();
    }

    /**
     * Notify that the crawler is paused.
     */
    public void paused (CrawlEvent event) {
        stop ();
    }

    /**
     * Create a new Frame containing a Statistics panel connected to a crawler.
     */ 
    public static Frame monitor (Crawler crawler) {
        Frame win = new ClosableFrame ("Statistics: " + crawler.getName ());

        Statistics stats = new Statistics ();
        crawler.addCrawlListener (stats);

        win.add ("Center", BorderPanel.wrap (stats, 5, 5, 5, 5));
        win.pack ();
        win.show ();

        return win;
    }

}
