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
import java.util.Hashtable;
import java.util.Vector;
import java.net.URL;
import java.net.MalformedURLException;
import websphinx.util.ClosableFrame;
import symantec.itools.awt.TreeView2;
import symantec.itools.awt.TreeNode2;
import java.awt.image.MemoryImageSource;
import websphinx.util.Constrain;
import websphinx.util.PopupDialog;
import websphinx.util.Colors;

public class WebOutline extends TreeView2 implements CrawlListener, LinkListener {

    Hashtable links = new Hashtable ();
       // maps Link -> TreeNode2
       
    /**
     * Make a WebOutline.
     */
    public WebOutline () {
        setPageIcon (defaultPageIcon);
        setLinkIcon (defaultRetrievingIcon);
        setRetrievingIcon (defaultRetrievingIcon);
        setErrorIcon (defaultErrorIcon);
    }


    /**
     * Show control panel for changing layout parameters.
     */
    public void showControlPanel () {
        new WorkbenchControlPanel (null, this).show ();
    }

    /**
     * Clear the outline.
     */
    public synchronized void clear () {
        super.clear ();
        links.clear ();
    }

    /**
     * Notify that the crawler started.
     */
    public void started (CrawlEvent event) {
    }

    /**
     * Notify that the crawler has stopped.
     */
    public void stopped (CrawlEvent event) {
    }

    /**
     * Notify that the crawler's state was cleared.
     */
    public void cleared (CrawlEvent event) {
        clear ();
    }

    /**
     * Notify that the crawler has timed out
     */
    public void timedOut (CrawlEvent event) {
    }

    /**
     * Notify that the crawler is paused
     */
    public void paused (CrawlEvent event) {
    }

    /**
     * Notify that a crawling event has occured.
     */
    public void crawled (LinkEvent event) {
        update (event.getLink ());
    }


    // Page filter
    
    static final int NO_LINKS = 0;         
        // Show no outgoing links

    static final int RETRIEVED_LINKS = 1;
        // Show only links that crawler started to retrieve

    static final int WALKED_LINKS = 2;
        // Show RETRIEVED_LINKS, plus links queued for retrieval

    static final int TREE_LINKS = 3;
        // Show WALKED_LINKS, plus links skipped by walk()

    static final int ALL_LINKS = 4;
        // Show TREE_LINKS, plus links to already-visited pages

    int defaultFilter = RETRIEVED_LINKS;

    // Change the filter of ALL nodes
    synchronized void setLinkFilter (int filter) {
        if (filter == defaultFilter)
            return;
           
        int old = defaultFilter;
        defaultFilter = filter;        
        reFilter (getRootNode (), old > filter);
        triggerRedraw ();
    }
        
    void reFilter (TreeNode2 n, boolean restrict) {
        for (; n != null; n = n.getSibling ()) {
            Link link = (Link)n.getDataObject();
            Page page = link.getPage ();
            if (page != null) {
                Link[] linkarray = page.getLinks ();

                if (restrict) {
                    // new mode is more restrictive; delete undesired children
                    for (int j=0; j<linkarray.length; ++j) {
                        if (!shouldDisplay (linkarray[j].getStatus())) {
                            TreeNode2 child = findNode (linkarray[j]);
                            if (child != null)
                                remove (child);
                        }
                    }
                }
                else {
                    // new mode is less restrictive; add children
                    for (int j=0; j<linkarray.length; ++j) {
                        update (linkarray[j]); // update() will check shouldDisplay()
                    }
                }
            }
            
            TreeNode2 c = n.getChild();
            if (c != null)
                reFilter (c, restrict);
        }
    }
    

    // check whether we want to display a link with this status
    boolean shouldDisplay (int status) {
        switch (status) {
           case LinkEvent.QUEUED:
           case LinkEvent.TOO_DEEP:
             return (defaultFilter > RETRIEVED_LINKS);
           case LinkEvent.SKIPPED:
             return (defaultFilter > WALKED_LINKS);
           case LinkEvent.ALREADY_VISITED:
             return false;
          case LinkEvent.RETRIEVING:
          case LinkEvent.DOWNLOADED:
          case LinkEvent.VISITED:
          case LinkEvent.ERROR:
            return true;
          default:
            return false;
        }
    }

    // Node rendering

    static final int TITLE = 0;
        // Show page title (or URL if not downloaded)

    static final int ABSOLUTE_URL = 1;
        // Show absolute URL

    static final int RELATIVE_URL = 2;
        // Show URL relative to parent

    int defaultRendering = TITLE;

    // Change the rendering of ALL nodes
    synchronized void setNodeRendering (int r) {
        defaultRendering = r;
        reRender (getRootNode ());
        triggerRedraw ();
    }

    void reRender (TreeNode2 n) {
        for (; n != null; n = n.getSibling ()) {
            update (n);
            
            TreeNode2 c = n.getChild();
            if (c != null)
                reRender (c);
        }
    }
    

    /**
     * Update all the links that the crawler reached from this link.
     * Any reachable links not present in the graph are added.
     */
    public void updateClosure (Link[] links) {
        if (links == null)
            return;
        for (int i=0; i < links.length; ++i) {
            Link link = links[i];
            int status = link.getStatus();

            if (status == LinkEvent.NONE)
                continue;

            update (link);

            if (status == LinkEvent.DOWNLOADED || status == LinkEvent.VISITED) {
                Page page = link.getPage();
                if (page != null)
                    updateClosure (page.getLinks ());
            }
        }
    }

    /**
     * Update the edge and node associated with a link.
     * If the link is not present in the graph, it is added.
     */
    public synchronized void update (Link link) {
        if (!shouldDisplay (link.getStatus ()))
            return;

        TreeNode2 n = findNode (link);
        if (n == null)
            add (link);
        else
            update (n);

        redraw ();
    }

    synchronized void add (Link link) {
        TreeNode2 n = new TreeNode2 ("");
        n.setDataObject (link);

        Page source = link.getSource ();
        Link origin = source.getOrigin ();
        TreeNode2 parent = findNode (origin);

        if (parent == null) {
            update (n);
            append (n);
        }
        else {
            update (n);
            insert (n, parent, CHILD);
            parent.expand ();
        }
        links.put (link, n);
    }

    void update (TreeNode2 n) {
        Link link = (Link)n.getDataObject ();
        Page page = link.getPage ();
        int status = link.getStatus ();

        Image icon = getIcon (LinkEvent.eventName[status]);
        n.setExpandedImage (icon);
        n.setCollapsedImage (icon);

        if (page == null) {
            // not downloaded yet
            String name = "";
            switch (defaultRendering) {
                case TITLE:
                case ABSOLUTE_URL:
                    name = link.getURL().toString();
                    break;
                case RELATIVE_URL: {
                    Link origin = link.getSource().getOrigin();
                    if (origin != null)
                        name = Link.relativeTo (origin.getURL(), link.getURL());
                    else
                        name = link.getURL().toString();
                    break;
                }
            }
            n.setText (name);

            n.setColor (Colors.parseColor (link.getLabel ("Workbench.color")));
        }
        else {
            String name = "";
            switch (defaultRendering) {
                case TITLE: {
                    name = page.getTitle ();
                    if (name == null)
                        name = link.getURL().toString();
                    break;
                }
                case ABSOLUTE_URL:
                    name = link.getURL().toString();
                    break;
                case RELATIVE_URL: {
                    Link origin = link.getSource().getOrigin();
                    if (origin != null)
                        name = Link.relativeTo (origin.getURL(), link.getURL());
                    else
                        name = link.getURL().toString();
                    break;
                }
            }
            n.setText (name);

            n.setColor (Colors.parseColor (page.getLabel ("Workbench.color")));
        }

    }

    TreeNode2 findNode (Link l) {
        if (l == null)
            return null;
        else
            return (TreeNode2)links.get (l);
    }

    /*
     * LinkView listeners
     */

    private Vector listeners = new Vector ();

    /**
     * Add a listener for LinkViewEvents.  A LinkViewEvent is sent every time a
     * node or edge in the graph is double-clicked.
     * @param listener Object that wants to receive LinkViewEvents 
     */
    public void addLinkViewListener (LinkViewListener listener) {
        if (!listeners.contains (listener))
            listeners.addElement (listener);
    }

    /**
     * Removes a listener from the set of LinkViewEvent listeners.  If it is not found in the set,
     * does nothing.
     *
     * @param listen a listener
     */
    public void removeLinkViewListener (CrawlListener listener) {
        listeners.removeElement (listener);
    }

    void fireEvent (Link link) {
        LinkViewEvent event = new LinkViewEvent (this, link);

        for (int j=0, len=listeners.size(); j<len; ++j) {
            LinkViewListener listen = (LinkViewListener)listeners.elementAt(j);
            listen.viewLink (event);
        }
    }

    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            TreeNode2 n = (TreeNode2)getSelectedNode();
            if (n != null)
                fireEvent ((Link)n.getDataObject());
        }
        else if (event.id == Event.MOUSE_DOWN && event.metaDown())
            showControlPanel ();
        else
            return super.handleEvent (event);
        return true;
    }
    
    public Link getSelectedLink () {
        TreeNode2 n = getSelectedNode();
        if (n != null)
            return (Link)n.getDataObject();
            
        return null;
    }
    

    /**
     * Create a new Frame containing a WebOutline connected to a crawler.
     */ 
    public static Frame monitor (Crawler crawler) {
        Frame win = new ClosableFrame ("Outline: " + crawler.getName ());

        WebOutline g = new WebOutline ();
        crawler.addCrawlListener (g);
        crawler.addLinkListener (g);

        win.add ("Center", g);
        win.pack ();
        win.show ();

        return win;
    }



    Hashtable icons = new Hashtable ();
       // maps String (CrawlEvent name or user-defined icon name) to Image

    Image pageIcon;
    Image linkIcon;
    Image retrievingIcon;
    Image errorIcon;

    /**
     * Get a named icon.
     * @param name Name of icon.
     * @return icon associated with the name, or null if name unknown.
     */
    public Image getIcon (String name) {
            return (Image)icons.get (name);
    }

    /**
     * Map a name to an icon.
     * @param name Name of icon.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public void setIcon (String name, Image icon) {
        if (icon != null)
           icons.put (name, icon);
        else
           icons.remove (name);
    }

    /**
     * Set the default icon used for pages.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public void setPageIcon (Image icon) {
        pageIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.VISITED], icon);
    }

    /**
     * Set the default icon used for links.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public void setLinkIcon (Image icon) {
        linkIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.QUEUED], icon);
        setIcon (LinkEvent.eventName[LinkEvent.ALREADY_VISITED], icon);
        setIcon (LinkEvent.eventName[LinkEvent.SKIPPED], icon);
    }

    /**
     * Set the default icon used for requests in progress.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public void setRetrievingIcon (Image icon) {
        retrievingIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.RETRIEVING], icon);
        setIcon (LinkEvent.eventName[LinkEvent.DOWNLOADED], icon); 
   }

    /**
     * Set the default icon used for failed requests.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public void setErrorIcon (Image icon) {
        errorIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.ERROR], icon);
    }


    public static Image defaultPageIcon;
    public static Image defaultLinkIcon;
    public static Image defaultRetrievingIcon;
    public static Image defaultErrorIcon;

    static int errorWidth = 16;
    static int errorHeight = 16;
    static int[] errorData = {
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xfffc0404, 0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 0xfffc0404, 
        0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xfffc0404, 
        0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xfffc0404, 0xfffc0404, 
        0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xfffc0404, 
        0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xffffff, 
        0xffffff, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xfffc0404, 0xfffc0404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
        0xffffff, 0xffffff, 0xffffff, 0xffffff
    };

    static int linkWidth = 16;
    static int linkHeight = 16;
    static int[] linkData = {
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xff343464, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xff343464, 0xffd4d4fc, 
        0xffc4c4c4, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xff343464, 0xff343464, 
        0xff343464, 0xffd4d4fc, 0xffd4d4fc, 0xffc4c4c4, 0xff6464cc, 0xff343464, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xff343464, 0xffccccfc, 0xff848484, 0xff343464, 0xffd4d4fc, 0xff848484, 
        0xff848484, 0xff6464cc, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xff343464, 0xff343464, 0xffd4d4fc, 0xffc4c4c4, 
        0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xff6464cc, 0xff6464cc, 0xff343464, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xff343464, 0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xff343464, 0xffd4d4fc, 
        0xffc4c4c4, 0xff6464cc, 0xff6464cc, 0xff343464, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xffccccfc, 0xffd4d4fc, 
        0xffc4c4c4, 0xff343464, 0xff343464, 0xff6464cc, 0xff6464cc, 0xff343464, 
        0xff343464, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xffc4c4c4, 0xff343464, 0xfcfcfc, 
        0xfcfcfc, 0xff343464, 0xff343464, 0xffd4d4fc, 0xffccccfc, 0xff343464, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xffccccfc, 0xffc4c4c4, 
        0xff343464, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xff040404, 0xff343464, 
        0xffccccfc, 0xffc4c4c4, 0xffc4c4c4, 0xff343464, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xff343464, 0xff040404, 0xff343464, 0xff343464, 0xff343464, 
        0xfcfcfc, 0xff040404, 0xff343464, 0xffccccfc, 0xffc4c4c4, 0xff343464, 
        0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 
        0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xffc4c4c4, 0xff343464, 0xff343464, 
        0xffccccfc, 0xffc4c4c4, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xffccccfc, 0xff040404, 
        0xff6464cc, 0xff6464cc, 0xff343464, 0xffccccfc, 0xff040404, 0xff343464, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xff343464, 0xffccccfc, 0xff040404, 0xff6464cc, 0xff6464cc, 
        0xff343464, 0xffccccfc, 0xff040404, 0xff343464, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xff343464, 0xffccccfc, 
        0xffc4c4c4, 0xff6464cc, 0xff343464, 0xff343464, 0xffccccfc, 0xffc4c4c4, 
        0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xff343464, 0xff040404, 0xff6464cc, 0xff343464, 
        0xff343464, 0xff343464, 0xff343464, 0xff343464, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xff343464, 0xff343464, 0xff343464, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
        0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc
    };

static int retrieveWidth = 16;
static int retrieveHeight = 16;
static int[] retrieveData = {
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xff008000, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 0xff008000, 
0xff008000, 0xff008000, 0xff008000, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
0xffffff, 0xffffff, 0xffffff, 0xffffff
};

static int pageWidth = 16;
static int pageHeight = 16;
static int[] pageData = {
0xffff, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 
0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 
0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff343434, 
0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xffffffff, 0xff000000, 0xffff, 
0xffff, 0xffff, 0xffff, 0xff343434, 0xfffcfcfc, 0xff343434, 
0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 
0xff343434, 0xffffffff, 0xffffffff, 0xff343434, 0xffff, 0xffff, 
0xffff, 0xff343434, 0xfffcfcfc, 0xff343434, 0xfffccc34, 0xfffccc34, 
0xff64ccfc, 0xff64ccfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xffffffff, 
0xffffffff, 0xffffffff, 0xff343434, 0xffff, 0xffff, 0xff343434, 
0xfffcfcfc, 0xff343434, 0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 
0xfffcfcfc, 0xfffcfcfc, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
0xff040404, 0xffff, 0xffff, 0xff343434, 0xfffcfcfc, 0xff343434, 
0xff9c6434, 0xff9c6434, 0xff9c6434, 0xff9c6434, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xfffcfcfc, 0xffffffff, 0xff000000, 0xff9c9c9c, 0xffff, 
0xffff, 0xff343434, 0xfffcfcfc, 0xff343434, 0xff9c6434, 0xff9c6434, 
0xff9c6434, 0xff9c6434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xff000000, 0xff9c9c9c, 0xffff, 0xffff, 0xff343434, 
0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff000000, 
0xff9c9c9c, 0xffff, 0xffff, 0xff343434, 0xfffcfcfc, 0xff040404, 
0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
0xff040404, 0xff040404, 0xfffcfcfc, 0xff000000, 0xff9c9c9c, 0xffff, 
0xffff, 0xff343434, 0xfffcfcfc, 0xffffffff, 0xffffffff, 0xffffffff, 
0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 
0xfffcfcfc, 0xff000000, 0xff9c9c9c, 0xffff, 0xffff, 0xff343434, 
0xffffffff, 0xffffffff, 0xfffcfcfc, 0xfffc3434, 0xfffcfcfc, 0xff040404, 
0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xfffcfcfc, 0xff000000, 
0xff9c9c9c, 0xffff, 0xffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff000000, 0xff9c9c9c, 0xffff, 
0xffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffc3434, 
0xfffcfcfc, 0xff000000, 0xff000000, 0xff040404, 0xff040404, 0xff040404, 
0xfffcfcfc, 0xff000000, 0xff9c9c9c, 0xffff, 0xffff, 0xff343434, 
0xfffcfcfc, 0xfffcfcfc, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 
0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffcfcfc, 0xff000000, 
0xff9c9c9c, 0xffff, 0xffff, 0xff000000, 0xff000000, 0xff000000, 
0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff000000, 
0xff000000, 0xff000000, 0xff000000, 0xff000000, 0xff9c9c9c, 0xffff, 
0xffff, 0xffff, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 
0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 
0xff9c9c9c, 0xff9c9c9c, 0xffff, 0xffff
};
  
    static {
        Toolkit tkit = Toolkit.getDefaultToolkit ();
        defaultPageIcon = tkit.createImage (
            new MemoryImageSource (pageWidth, pageHeight, 
                                   pageData, 0, pageWidth));
        defaultLinkIcon = tkit.createImage (
            new MemoryImageSource (linkWidth, linkHeight, 
                                   linkData, 0, linkWidth));
        defaultRetrievingIcon = tkit.createImage (
            new MemoryImageSource (retrieveWidth, retrieveHeight, 
                                   retrieveData, 0, retrieveWidth));
        defaultErrorIcon = tkit.createImage (
            new MemoryImageSource (errorWidth, errorHeight, 
                                   errorData, 0, errorWidth));
    }    

}

