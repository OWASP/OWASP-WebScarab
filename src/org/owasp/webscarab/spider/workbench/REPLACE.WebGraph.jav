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
import java.applet.Applet;
import java.applet.AppletContext;
import java.net.URL;
import java.net.MalformedURLException;
import websphinx.util.Colors;
import websphinx.util.GraphLayout;
import websphinx.util.ClosableFrame;
import java.awt.image.MemoryImageSource;
import graph.Graph;
import websphinx.util.Constrain;
import websphinx.util.PopupDialog;

// FIX: connect ALREADY_VISITED links to page

public class WebGraph extends GraphLayout implements CrawlListener, LinkListener {

    Hashtable links = new Hashtable ();
       // maps Link -> WebNode (for root links) or WebEdge (for internal links)

    /**
     * Make a WebGraph.
     */
    public WebGraph () {
        setPageIcon (defaultPageIcon);
        setLinkIcon (defaultLinkIcon);
        setRetrievingIcon (defaultRetrievingIcon);
        setErrorIcon (defaultErrorIcon);
    }

    // Filtering of a node's outgoing links 

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

    // Change the filter of a node
    synchronized void setLinkFilter (WebNode node, int filter) {
        if (filter == node.filter)
            return;

        Page page = node.link.getPage ();
        if (page != null) {
            Link[] linkarray = page.getLinks ();

            if (filter < node.filter) {
                // new mode is more restrictive; delete undesired edges
                for (int j=0; j<linkarray.length; ++j) {
                    if (!shouldDisplay (filter, linkarray[j].getStatus())) {
                        WebEdge edge = (WebEdge)links.get (linkarray[j]);
                        if (edge != null) {
                            removeNode ((WebNode)edge.to);
                            removeEdge (edge);
                            links.remove (linkarray[j]);
                        }
                       }
                }
            }
            else if (filter > node.filter) {
                // new mode is less restrictive; add edges
                for (int j=0; j<linkarray.length; ++j) {
                    update (linkarray[j]); // update() will check shouldDisplay()
                }
            }
        }

        node.filter = filter;
    }

    // Change the filter of ALL nodes
    synchronized void setLinkFilter (int filter) {
        defaultFilter = filter;
        Graph graph = getGraph ();
        for (int i=0; i<graph.sizeNodes; ++i) {
            WebNode n = (WebNode)graph.nodes[i];
            setLinkFilter (n, filter);
        }
    }

    // Node rendering

    static final int ICON = 0;
        // Show an icon

    static final int TITLE = 1;
        // Show page title (or URL if not downloaded)

    static final int ABSOLUTE_URL = 2;
        // Show absolute URL

    static final int RELATIVE_URL = 3;
        // Show URL relative to parent

    int defaultRendering = ICON;

    // Change the rendering of a node
    void setNodeRendering (WebNode n, int r) {
        n.rendering = r;
        update(n);

        repaint ();
    }

    // Change the rendering of ALL nodes
    synchronized void setNodeRendering (int r) {
        defaultRendering = r;

        Graph graph = getGraph ();
        for (int i=0; i<graph.sizeNodes; ++i) {
            WebNode n = (WebNode)graph.nodes[i];
            n.rendering = r;
            update (n);
        }

        changedGraph ();
    }

    /**
     * Show control panel for changing graph layout parameters.
     */
    public void showControlPanel () {
        new WorkbenchControlPanel (this, null).show ();
    }

    /**
     * Clear the graph display.
     */
    public synchronized void clear () {
        links.clear ();
        super.clear ();
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

    // check whether we want to display a link with this status
    boolean shouldDisplay (int filter, int status) {
        switch (status) {
           case LinkEvent.QUEUED:
           case LinkEvent.TOO_DEEP:
             return (filter > RETRIEVED_LINKS);
           case LinkEvent.SKIPPED:
             return (filter > WALKED_LINKS);
           case LinkEvent.ALREADY_VISITED:
             return (filter > TREE_LINKS);
          case LinkEvent.RETRIEVING:
          case LinkEvent.DOWNLOADED:
          case LinkEvent.VISITED:
          case LinkEvent.ERROR:
            return true;
          default:
            return false;
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
        Object obj = links.get (link);

        if (obj == null) {
            add (link);
        }
        else if (obj instanceof WebEdge) {
            WebEdge e = (WebEdge) obj;
            update (e);
            update ((WebNode)e.to);
        }
        else {
            // obj instanceof WebNode
            update ((WebNode)obj);
        }

        repaint ();
    }

    synchronized void add (Link link) {
        WebNode n = new WebNode (link, defaultFilter, defaultRendering);
        WebNode parent = findParent (link);
        
        if (parent == null) {
            links.put (link, n);
            update (n);
            addNode (n);

            if (getGraph().sizeNodes == 1) {
                // root node of first tree -- put it at the origin and fix it
                n.fixed = true;
                placeNodeOnGraph (n, 0, 0);
            }
            else {
                // root node of an additional tree -- drop it randomly
                // within window
                
                Dimension d = size ();
                
                int x = (int)(Math.random() * d.width);
                int y = (int)(Math.random() * d.height);
                placeNodeOnScreen (n, x, y);
            }
        }
        else {
            // check if parent's filter allows this link to be displayed
            if (!shouldDisplay (parent.filter, link.getStatus ()))
                return;

            // hang the node off its parent in a random direction
            double len = getRestLength();
            double angle = Math.random () * 2 * Math.PI;
            double x = parent.x + len*Math.cos(angle);
            double y = parent.y + len*Math.sin(angle);

            update (n);
            addNode (n);
            placeNodeOnGraph (n, x, y);

            WebEdge e = new WebEdge (link, parent, n);
            links.put (link, e);
            update (e);
            addEdge (e);
        }
    }

    void update (WebEdge e) {
        e.color = Colors.parseColor (e.link.getLabel ("Workbench.color"));
        e.thick = e.link.hasLabel ("Workbench.thick");
    }

    void update (WebNode n) {
        Page page = n.link.getPage ();
        int status = n.link.getStatus ();

        if (page == null) {
            // not downloaded yet
            switch (n.rendering) {
            case ICON:
                n.name = null;
                n.icon = getIcon (LinkEvent.eventName[status]);
                break;
            case TITLE:
            case ABSOLUTE_URL:
                n.name = n.link.getURL().toString();
                n.icon = null;
                break;
            case RELATIVE_URL: {
                Link origin = n.link.getSource().getOrigin();
                if (origin != null)
                    n.name = Link.relativeTo (origin.getURL(), n.link.getURL());
                else
                    n.name = n.link.getURL().toString();
                n.icon = null;
                break;
            }
            }
        }
        else {
            switch (n.rendering) {
            case ICON:
                n.name = null;
                n.icon = getIcon (page.getLabel ("Workbench.icon", 
                                                 LinkEvent.eventName[status]));
                break;
            case TITLE:
                n.name = page.getTitle ();
                if (n.name == null)
                    n.name = "[" + n.link.getURL().toString() + "]";
                n.icon = null;
                break;
            case ABSOLUTE_URL:
                n.name = n.link.getURL().toString();
                n.icon = null;
                break;
            case RELATIVE_URL: {
                Link origin = n.link.getSource().getOrigin();
                if (origin != null)
                    n.name = Link.relativeTo (origin.getURL(), n.link.getURL());
                else
                    n.name = n.link.getURL().toString();
                n.icon = null;
                break;
            }
            }
            n.color = Colors.parseColor (page.getLabel ("Workbench.color"));
            n.scale = page.getNumericLabel ("Workbench.size", 
                            new Integer (1)).doubleValue ();
        }

        if (n.icon == null) {
            FontMetrics fm = getFontMetrics ();
            n.width = fm.stringWidth (n.name) + 10;
            n.height = fm.getHeight () + 4;
        }
        else {
            n.width = (int)(n.icon.getWidth(this) * n.scale);
            n.height = (int)(n.icon.getHeight(this) * n.scale);
        }
    }

    WebEdge findEdge (Link l) {
        if (l == null)
                return null;
            Object obj = links.get (l);
            if (obj instanceof WebEdge)
                return (WebEdge)obj;
            else
                return null;
    }        

    WebNode findNode (Link l) {
        if (l == null)
            return null;
        Object obj = links.get (l);
        if (obj instanceof WebEdge)
            return (WebNode)((WebEdge)obj).to;
        else
            return (WebNode)obj;
    }
    
    WebNode findParent (Link l) {
        if (l == null)
            return null;
        Page source = l.getSource ();
        Link origin	= source.getOrigin ();
        return findNode (origin);
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

    void doubleClick (int x, int y) {
        Object over = pick (x, y);
        if (over != null) {
            Link link;
            if (over instanceof WebNode)
                link = ((WebNode)over).link;
            else
                link = ((WebEdge)over).link;
            fireEvent (link);
        }
    }
        
    public boolean handleEvent (Event event) {
        if (event.id == Event.MOUSE_DOWN && event.clickCount == 2) {
            doubleClick (event.x, event.y);
        }
        else
            return super.handleEvent (event);
        return true;
    }
    
    public Link getSelectedLink () {
        WebNode n = (WebNode)getSelectedNode();
        if (n != null)
            return n.link;
            
        WebEdge e = (WebEdge)getSelectedEdge();
        if (e != null)
            return e.link;
            
        return null;
    }
    
    /**
     * Create a new Frame containing a WebGraph connected to a crawler.
     */ 
    public static Frame monitor (Crawler crawler) {
        Frame win = new ClosableFrame ("Graph: " + crawler.getName ());

        WebGraph g = new WebGraph ();
        crawler.addCrawlListener (g);
        crawler.addLinkListener (g);
        g.setNodeCharge (1000);
        g.setRestLength (50);

        win.add ("Center", g);
        win.pack ();
        win.show ();

        return win;
    }

    static String[] getTip (Link link) {
        Vector result = new Vector ();

        String exception = link.getLabel ("exception");
        if (exception != null && exception.length() > 0)
            result.addElement ("*** " + exception);

        String anchor = link.toText ();
        if (anchor != null && anchor.length() > 0)
            result.addElement (anchor);

        String url = link.getURL ().toString ();
        if (url != null && url.length() > 0)
            result.addElement (url);

        String labels = link.getObjectLabels ();
        if (labels != null && labels.length() > 0)
            result.addElement (labels);

        String[] tip = new String[result.size ()];
        result.copyInto (tip);
        return tip;
    }

    static String[] getTip (Page page) {
        Vector result = new Vector ();

        String title = page.getTitle ();
        if (title != null && title.length() > 0)
            result.addElement (title);

        String url = page.getURL ().toString();
        if (url != null && url.length() > 0)
            result.addElement (url);

        String labels = page.getObjectLabels ();
        if (labels != null && labels.length() > 0)
            result.addElement (labels);

        String[] tip = new String[result.size ()];
        result.copyInto (tip);
        return tip;
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
    public synchronized Image getIcon (String name) {
            return (Image)icons.get (name);
    }

    /**
     * Map a name to an icon.
     * @param name Name of icon.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public synchronized void setIcon (String name, Image icon) {
        if (icon != null)
           icons.put (name, icon);
        else
           icons.remove (name);
    }

    /**
     * Set the default icon used for pages.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public synchronized void setPageIcon (Image icon) {
        pageIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.VISITED], icon);
    }

    /**
     * Set the default icon used for links.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public synchronized void setLinkIcon (Image icon) {
        linkIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.QUEUED], icon);
        setIcon (LinkEvent.eventName[LinkEvent.TOO_DEEP], icon);
        setIcon (LinkEvent.eventName[LinkEvent.ALREADY_VISITED], icon);
        setIcon (LinkEvent.eventName[LinkEvent.SKIPPED], icon);
    }

    /**
     * Set the default icon used for requests in progress.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public synchronized void setRetrievingIcon (Image icon) {
        retrievingIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.RETRIEVING], icon);
        setIcon (LinkEvent.eventName[LinkEvent.DOWNLOADED], icon); 
   }

    /**
     * Set the default icon used for failed requests.
     * @param icon Icon image.  If null, mapping is deleted.
     */
    public synchronized void setErrorIcon (Image icon) {
        errorIcon = icon;
        setIcon (LinkEvent.eventName[LinkEvent.ERROR], icon);
    }


    public static Image defaultPageIcon;
    public static Image defaultLinkIcon;
    public static Image defaultRetrievingIcon;
    public static Image defaultErrorIcon;

    static int linkWidth = 17;
    static int linkHeight = 17;
    static int[] linkData = {
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343464, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff343464, 
    0xffd4d4fc, 0xffc4c4c4, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 
    0xff343464, 0xff343464, 0xff343464, 0xffd4d4fc, 0xffd4d4fc, 0xffc4c4c4, 
    0xff6464cc, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xffccccfc, 0xff848484, 
    0xff343464, 0xffd4d4fc, 0xff848484, 0xff848484, 0xff6464cc, 0xff343464, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff343464, 0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xff343464, 0xffd4d4fc, 
    0xffc4c4c4, 0xff6464cc, 0xff6464cc, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 
    0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xff343464, 0xffd4d4fc, 0xffc4c4c4, 
    0xff6464cc, 0xff6464cc, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xffccccfc, 0xffd4d4fc, 
    0xffc4c4c4, 0xff343464, 0xff343464, 0xff6464cc, 0xff6464cc, 0xff343464, 
    0xff343464, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343464, 0xffd4d4fc, 0xffc4c4c4, 0xffc4c4c4, 0xff343464, 
    0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff343464, 0xffd4d4fc, 0xffccccfc, 
    0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 
    0xffccccfc, 0xffc4c4c4, 0xff343464, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 
    0xff040404, 0xff343464, 0xffccccfc, 0xffc4c4c4, 0xffc4c4c4, 0xff343464, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff040404, 
    0xff343464, 0xff343464, 0xff343464, 0xfffcfcfc, 0xff040404, 0xff343464, 
    0xffccccfc, 0xffc4c4c4, 0xff343464, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff343464, 0xffd4d4fc, 
    0xffc4c4c4, 0xffc4c4c4, 0xff343464, 0xff343464, 0xffccccfc, 0xffc4c4c4, 
    0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xffccccfc, 0xff040404, 0xff6464cc, 
    0xff6464cc, 0xff343464, 0xffccccfc, 0xff040404, 0xff343464, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343464, 0xffccccfc, 0xff040404, 0xff6464cc, 0xff6464cc, 
    0xff343464, 0xffccccfc, 0xff040404, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 
    0xffccccfc, 0xffc4c4c4, 0xff6464cc, 0xff343464, 0xff343464, 0xffccccfc, 
    0xffc4c4c4, 0xff343464, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff040404, 
    0xff6464cc, 0xff343464, 0xff343464, 0xff343464, 0xff343464, 0xff343464, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343464, 0xff343464, 0xff343464, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc
    };

    static int pageWidth = 22;
    static int pageHeight = 26;
    static int[] pageData = {
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xff343434, 
    0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xff343434, 
    0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343434, 0xfffcfcfc, 0xff343434, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 
    0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343434, 0xff343434, 0xff343434, 0xff343434, 0xff343434, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343434, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 
    0xfffccc34, 0xfffccc34, 0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff343434, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xfffccc34, 0xff64ccfc, 
    0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 0xfffcfcfc, 0xfffcfcfc, 0xff040404, 
    0xff343434, 0xff040404, 0xff343434, 0xff040404, 0xff343434, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xff343434, 0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 0xff64ccfc, 
    0xff64ccfc, 0xfffcfcfc, 0xfffcfcfc, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 
    0xff9c6434, 0xff9c6434, 0xff9c6434, 0xff9c6434, 0xff9c6434, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 
    0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff343434, 0xff9c6434, 0xff9c6434, 
    0xff9c6434, 0xff9c6434, 0xff9c6434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffc3434, 0xfffcfcfc, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffc3434, 
    0xfffcfcfc, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xff343434, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 0xfffcfcfc, 
    0xff9c9c9c, 0xff040404, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff343434, 0xff343434, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 
    0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 
    0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff9c9c9c, 0xff343434, 0xff040404, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xff040404, 
    0xff040404, 0xff040404, 0xff040404, 0xff040404, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 
    0xffffff, 0xffffff
    };

    static int retrieveWidth = 8;
    static int retrieveHeight = 8;
    static int[] retrieveData = {
        0xffffff, 0xffffff, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xffffff, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xffffff, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 0xff008000, 
        0xff008000, 0xffffff, 0xffffff, 0xffffff, 0xff008000, 0xff008000, 
        0xff008000, 0xff008000, 0xffffff, 0xffffff
    };

    static int errorWidth = 8;
    static int errorHeight = 8;
    static int[] errorData = {
    0xfffc0404, 0xfffc0404, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 
    0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 
    0xfcfcfc, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 0xfffc0404, 
    0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 
    0xfcfcfc, 0xfcfcfc, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 
    0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfffc0404, 0xfffc0404, 
    0xfffc0404, 0xfffc0404, 0xfcfcfc, 0xfcfcfc, 0xfcfcfc, 0xfffc0404, 
    0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 
    0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 0xfcfcfc, 0xfffc0404, 
    0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfffc0404, 0xfcfcfc, 0xfcfcfc, 
    0xfcfcfc, 0xfcfcfc, 0xfffc0404, 0xfffc0404
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

