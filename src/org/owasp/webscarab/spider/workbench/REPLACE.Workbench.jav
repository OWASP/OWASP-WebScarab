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

import java.awt.*;
import java.io.*;
import java.net.URL;
import websphinx.*;
import websphinx.util.Constrain;
import websphinx.util.PopupDialog;
import websphinx.util.TabPanel;
import websphinx.util.BorderPanel;
import websphinx.util.ClosableFrame;

public class Workbench extends Panel implements CrawlListener {

    Crawler crawler;

    String currentFilename = "";

    // panel wrappers
    Panel workbenchPanel; // contains menuPanel, configPanel, buttonPanel
    GridBagConstraints workbenchConstraints;
    WorkbenchVizPanel vizPanel; // contains graph, outline, and statistics
    GridBagConstraints vizConstraints;

    // GUI event listeners
    WebGraph graph;
    WebOutline outline;
    Statistics statistics;
    EventLog logger;

    // menu bar (for frame mode)
    MenuBar menubar;
    Menu fileMenu;
    MenuItem newCrawlerItem;
    MenuItem openCrawlerItem;
    MenuItem saveCrawlerItem;
    MenuItem createCrawlerItem;
    MenuItem exitItem;

    // menu panel (for container mode)
    Panel menuPanel;
    Button newCrawlerButton;
    Button openCrawlerButton;
    Button saveCrawlerButton;
    Button createCrawlerButton;

    WorkbenchTabPanel configPanel;
    Panel simplePanel;
    Panel crawlPanel;
    Panel limitsPanel;
    Panel classifiersPanel;
    Panel linksPanel;
    Panel actionPanel;

    CrawlerEditor crawlerEditor;
    ClassifierListEditor classifierListEditor;
    DownloadParametersEditor downloadParametersEditor;
    LinkPredicateEditor linkPredicateEditor;
    PagePredicateEditor pagePredicateEditor;
    ActionEditor actionEditor;
    SimpleCrawlerEditor simpleCrawlerEditor;

    boolean advancedMode = false;
    boolean tornOff = false;
    
    Button startButton, pauseButton, stopButton, clearButton;
    
    boolean allowExit;

    // Frames
    Frame workbenchFrame;
    Frame vizFrame;
    
    static final int MARGIN = 8;  // pixel border around configPanel
    
    public Workbench () {
        this (makeDefaultCrawler ());
        return;
    }
    
    private static Crawler makeDefaultCrawler () {
        Crawler c = new Crawler ();
        c.setDomain (Crawler.SUBTREE);
        return c;
    }
    
    public Workbench (String filename) throws Exception {
        this (loadCrawler (new FileInputStream (filename)));
    }

    public Workbench (URL url) throws Exception {
        this (loadCrawler (url.openStream ())); // FIX: Netscape 4 refuses to load off local disk
    }
   
    public Workbench (Crawler _crawler) {
        Browser browser = Context.getBrowser ();

        setLayout (new BorderLayout ());
        setBackground (Color.lightGray);
        
        setLayout (new GridLayout (2, 1));
        
        add (workbenchPanel = new Panel ());
        workbenchPanel.setLayout (new GridBagLayout ());
        
        // menu buttons panel
        makeMenus ();
        Constrain.add (workbenchPanel, menuPanel, Constrain.labelLike (0, 0));
        
        // configuration panel                
        configPanel = new WorkbenchTabPanel ();
        Constrain.add (workbenchPanel, configPanel, Constrain.areaLike (0, 1));
        simplePanel = makeSimplePanel();
        crawlPanel = makeCrawlPanel();
        linksPanel = makeLinksPanel();
        actionPanel = makeActionPanel();
        classifiersPanel = makeClassifiersPanel ();
        limitsPanel = makeLimitsPanel ();

        // start/pause/stop button panel
        Constrain.add (workbenchPanel, makeButtonPanel(), Constrain.fieldLike (0, 2));

        // visualization panel
        add (vizPanel = new WorkbenchVizPanel (this));

        // graph visualization
        graph = new WebGraph ();
        graph.setBackground (Color.white);
        if (browser != null)
            graph.addLinkViewListener (browser);
        vizPanel.addTabPanel ("Graph", true, graph);

        // outline visualization
        outline = new WebOutline ();
        outline.setBackground (Color.white);
        if (browser != null)
            outline.addLinkViewListener (browser);
        vizPanel.addTabPanel ("Outline", true, outline);

        // statistics visualization
        statistics = new Statistics ();
        Panel p = new Panel ();
        p.setLayout (new FlowLayout());
        p.add (statistics);
        vizPanel.addTabPanel ("Statistics", true, p);

        // event logger (sends to System.err -- no GUI presence)
        logger = new EventLog ();

        // now that the GUI is set up, we can initialize it with the
        // crawler
        setCrawler (_crawler);        
    }

    public Frame makeFrame () {
        if (workbenchFrame == null) {
            Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
            workbenchFrame = new WorkbenchFrame (this);
            workbenchFrame.setForeground (getForeground());
            workbenchFrame.setBackground (getBackground());
            workbenchFrame.setFont (getFont());
            workbenchFrame.setTitle ("Crawler Workbench: " + 
                                     (crawler != null ? crawler.getName() : ""));
            workbenchFrame.setLayout (new GridLayout (1,1));
            workbenchFrame.add (this);
            workbenchPanel.remove (menuPanel);
            workbenchFrame.setMenuBar (menubar);
            workbenchFrame.reshape (0, 0, 
                                    Math.min (550, screen.width),
                                    screen.height - 50);
        }
        return workbenchFrame;
    }

    public void setAllowExit (boolean yes) {
        allowExit = yes;
    }
    
    public boolean getAllowExit () {
        return allowExit;
    }
    
    public synchronized void setAdvancedMode (boolean adv) {
        if (advancedMode == adv)
            return;

        configureCrawler ();  // write current mode's settings back to crawler
        advancedMode = adv;
        setCrawler (crawler); // read new mode's settings from crawler

        configPanel.advancedButton.setLabel (advancedMode 
                                             ? "<< Simple" : ">> Advanced");
        validate ();
    }
    
    public boolean getAdvancedMode () {
        return advancedMode;
    }

    /* * * * * * * * * * * * * * * * * * * * * * *
     *   GUI Construction
     * * * * * * * * * * * * * * * * * * * * * * */

    static void setVisible (Component comp, boolean visible) {
        if (visible)
            comp.show();
        else
            comp.hide ();
    }

    static void setEnabled (Component comp, boolean enabled) {
        if (enabled)
            comp.enable();
        else
            comp.disable();
    }

    static void setEnabled (MenuItem item, boolean enabled) {
        if (enabled)
            item.enable();
        else
            item.disable();
    }

    Panel makeMenus () {
        // menubar
        menubar = new MenuBar ();
        menuPanel = new Panel ();
        menuPanel.setLayout (new FlowLayout()); // for horizontal layout

        // FILE menu
        menubar.add (fileMenu = new Menu ("File"));
        
        // File/New Crawler
        fileMenu.add (newCrawlerItem = new MenuItem ("New Crawler"));
        menuPanel.add (newCrawlerButton = new Button ("New"));
               
        // File/Open Crawler
        fileMenu.add (openCrawlerItem = new MenuItem ("Open Crawler..."));
        menuPanel.add (openCrawlerButton = new Button ("Open..."));
        

        // File/Save Crawler
        fileMenu.add (saveCrawlerItem = new MenuItem ("Save Crawler..."));
        menuPanel.add (saveCrawlerButton = new Button ("Save..."));

        // File/Create Crawler
        fileMenu.add (createCrawlerItem = new MenuItem ("Create Crawler From Class..."));
        menuPanel.add (createCrawlerButton = new Button ("Create..."));
               

        // File/Exit
        fileMenu.add (exitItem = new MenuItem ("Exit"));
        
        return menuPanel;
    }
        
    private Panel makeSimplePanel () {
        return simpleCrawlerEditor = new SimpleCrawlerEditor ();
    }

    // FIX: add onlyHyperLinks, synchronous, ignoreVisitedLinks
    private Panel makeCrawlPanel () {
        return crawlerEditor = new CrawlerEditor ();
    }

    private Panel makeLinksPanel () {
        Panel panel = new Panel ();
        panel.setLayout (new GridBagLayout ());

        Constrain.add (panel, new Label("Follow:"), Constrain.labelLike (0, 0));
        Constrain.add (panel, linkPredicateEditor = new LinkPredicateEditor (),
             Constrain.areaLike (1, 0));

        return panel;
    }

    private Panel makeActionPanel () {
        Panel panel = new Panel ();
        panel.setLayout (new GridBagLayout ());

        Constrain.add (panel, new Label ("Action:"), Constrain.labelLike (0, 0));
        Constrain.add (panel, actionEditor = new ActionEditor (), Constrain.areaLike (1, 0));

        Constrain.add (panel, new Label("on pages:"), Constrain.labelLike (0, 1));
        Constrain.add (panel, pagePredicateEditor = new PagePredicateEditor (),
             Constrain.areaLike (1, 1));
        return panel;
    }
    
    private Panel makeClassifiersPanel () {
        classifierListEditor = new ClassifierListEditor ();
        return classifierListEditor;
    }

    private Panel makeLimitsPanel () {
        downloadParametersEditor = new DownloadParametersEditor ();
        return downloadParametersEditor;
    }

    private Panel makeButtonPanel () {
        Panel panel = new Panel ();
        panel.setLayout (new FlowLayout ());
        
        panel.add (startButton = new Button ("Start"));
        panel.add (pauseButton = new Button ("Pause"));
        panel.add (stopButton = new Button ("Stop"));
        panel.add (clearButton = new Button ("Clear"));
        enableButtons (true, false, false, false);
        return panel;
    }

    String getCrawlerClassName (String label) {
        String className = label;
        if (className != null) {
            if (className.equals ("Crawler"))
                className = "websphinx.Crawler";
            else if (className.equals ("Load Class..."))
                className = null;
        }
        return className;
    }    
       
    public boolean handleEvent (Event event) {
        if (doEvent (event))
            return true;
        else
            return super.handleEvent (event);
    }

    boolean doEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target instanceof MenuItem) {
                MenuItem item = (MenuItem)event.target;
                
                if (item == newCrawlerItem)
                    newCrawler ();
                else if (item == openCrawlerItem)
                    openCrawler ();
                else if (item == saveCrawlerItem)
                    saveCrawler ();
                else if (item == createCrawlerItem)
                    createCrawler (null);
                else if (item == exitItem)
                    close ();
                else
                    return false;
            }
            else if (event.target == newCrawlerButton)
                newCrawler ();
            else if (event.target == openCrawlerButton)
                openCrawler ();
            else if (event.target == saveCrawlerButton)
                saveCrawler ();
            else if (event.target == createCrawlerButton)
                createCrawler (null);
            else if (event.target == configPanel.advancedButton)
                setAdvancedMode (!advancedMode);
            else if (event.target == vizPanel.optionsButton)
                new WorkbenchControlPanel (graph, outline).show ();
            else if (event.target == vizPanel.tearoffButton)
                if (tornOff)
                    dockVisualizations ();
                else
                    tearoffVisualizations ();
            else if (event.target == startButton)
                start ();
            else if (event.target == pauseButton)
                pause ();
            else if (event.target == stopButton)
                stop ();
            else if (event.target == clearButton)
                clear ();
            else
                return false;
        }
        else
            return false;
            
        return true;
    }

    
    /* * * * * * * * * * * * * * * * * * * * * * *
     *   Command handling
     * * * * * * * * * * * * * * * * * * * * * * */
    
    protected void finalize () {
        // FIX: dispose of frames
    }
    
    void close () {
        if (!allowExit)
            return;
        
        // FIX: dispose of frames

        if (Context.isApplication()) {
            Runtime.runFinalizersOnExit (true);
            System.exit (0);
        }
    }

    public void refresh () {
        graph.updateClosure (crawler.getCrawledRoots ());
        outline.updateClosure (crawler.getCrawledRoots ());
    }

    void connectVisualization (Crawler crawler, Object viz, boolean linksToo) {
        if (viz instanceof CrawlListener)
            crawler.addCrawlListener ((CrawlListener)viz);
        if (linksToo && viz instanceof LinkListener)
            crawler.addLinkListener ((LinkListener)viz);
    }

    void disconnectVisualization (Crawler crawler, Object viz, boolean linksToo) {
        if (viz instanceof CrawlListener)
            crawler.removeCrawlListener ((CrawlListener)viz);
        if (linksToo && viz instanceof LinkListener)
            crawler.removeLinkListener ((LinkListener)viz);
    }


    void showVisualization (Object viz) {
        if (viz == graph)
            graph.start ();
    }
    
    void hideVisualization (Object viz) {
        if (viz == graph)
            graph.stop ();
    }

    void tearoffVisualizations () {
        if (tornOff)
            return;
            
        if (vizFrame == null) {
            Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
            vizFrame = new WorkbenchVizFrame (this);
            vizFrame.setForeground (getForeground());
            vizFrame.setBackground (getBackground());
            vizFrame.setFont (getFont());
            vizFrame.setTitle ("Visualization: " + 
                               (crawler != null ? crawler.getName() : ""));
            vizFrame.setLayout (new GridLayout (1,1));
            vizFrame.reshape (0, 0,
                              Math.min (550, screen.width), 
                              screen.height/2);
        }
        
        remove (vizPanel);
        setLayout (new GridLayout (1,1));
        validate ();

        vizFrame.add (vizPanel);
        setVisible (vizFrame, true);

        vizPanel.tearoffButton.setLabel ("Glue Back");
        
        tornOff = true;
    }

    void dockVisualizations () {
        if (!tornOff)
            return;
            
        setVisible (vizFrame, false);
        vizFrame.remove (vizPanel);
        
        setLayout (new GridLayout (2, 1));
        add (vizPanel);
        validate ();
        
        vizPanel.tearoffButton.setLabel ("Tear Off");
        
        tornOff = false;
    }

    void newCrawler () {
        setCrawler (makeDefaultCrawler ());
        currentFilename = "";
    }
    
    void createCrawler (String className) {
        if (className == null || className.length() == 0) {
            className = PopupDialog.ask (workbenchPanel,
                                         "New Crawler",
                                         "Create a Crawler of class:",
                                         crawler.getClass().getName()
                                         );
            if (className == null)
                return;
        }
        
        try {
            Class crawlerClass = (Class)Class.forName (className);
            Crawler newCrawler = (Crawler)crawlerClass.newInstance ();
            
            setCrawler (newCrawler);
            currentFilename = "";
        } catch (Exception e) {
            PopupDialog.warn (workbenchPanel, 
                              "Error", 
                              e.toString());
            return;
        }        
    }

    
    void openCrawler () {
        String fn = PopupDialog.askFilename (workbenchPanel, "Open Crawler", "", true);
        if (fn != null)
            openCrawler (fn);
    }

    void openCrawler (String filename) {
        try {
            setCrawler (loadCrawler (SecurityPolicy.getPolicy().readFile (new File (filename))));
            currentFilename = filename;
        } catch (Exception e) {
            PopupDialog.warn (workbenchPanel, 
                              "Error", 
                              e.toString());
        } 
    }

    void openCrawler (URL url) {
        try {
            setCrawler (loadCrawler (SecurityPolicy.getPolicy().openConnection (url).getInputStream ()));
            currentFilename = "";
        } catch (Exception e) {
            PopupDialog.warn (workbenchPanel, 
                              "Error", 
                              e.toString());
        } 
    }
    
    static Crawler loadCrawler (InputStream stream) throws Exception {
        ObjectInputStream in = new ObjectInputStream (stream);
        Crawler loadedCrawler = (Crawler)in.readObject ();
        in.close ();
        return loadedCrawler;
    }

    void saveCrawler () {
        String fn = PopupDialog.askFilename (workbenchPanel, "Save Crawler As", currentFilename, true);
        if (fn != null)
            saveCrawler (fn);
    }

    void saveCrawler (String filename) {       
        configureCrawler ();
        
        try {
            ObjectOutputStream out = 
                new ObjectOutputStream (SecurityPolicy.getPolicy().writeFile (new File (filename), false));
            out.writeObject ((Object)crawler);
            out.close ();

            currentFilename = filename;
        } catch (Exception e) {
            PopupDialog.warn (workbenchPanel, 
                              "Error", 
                              e.toString());
        } 
    }

    void configureCrawler () {
        if (advancedMode) {
            crawlerEditor.getCrawler ();
            classifierListEditor.getCrawler ();
            crawler.setDownloadParameters (downloadParametersEditor.getDownloadParameters ());
            if (advancedMode) {
                crawler.setLinkPredicate (linkPredicateEditor.getLinkPredicate ());
                crawler.setPagePredicate (pagePredicateEditor.getPagePredicate ());
                crawler.setAction (actionEditor.getAction());
            }
        }
        else
            simpleCrawlerEditor.getCrawler ();
    }

    void enableButtons (boolean fStart, boolean fPause, boolean fStop, boolean fClear) {
        setEnabled (startButton, fStart);
        setEnabled (pauseButton, fPause);
        setEnabled (stopButton, fStop);
        setEnabled (clearButton, fClear);
    }        

    /* * * * * * * * * * * * * * * * * * * * * * *
     *   Changing the crawler 
     * * * * * * * * * * * * * * * * * * * * * * */
            
    public void setCrawler (Crawler _crawler) {
        if (crawler != _crawler) {
            if (crawler != null) {
                clear ();
                disconnectVisualization (crawler, this, false);
                disconnectVisualization (crawler, graph, true);
                disconnectVisualization (crawler, outline, true);
                disconnectVisualization (crawler, statistics, false);
                disconnectVisualization (crawler, logger, true);
            }
        
            connectVisualization (_crawler, this, false);
            connectVisualization (_crawler, graph, true);
            connectVisualization (_crawler, outline, true);
            connectVisualization (_crawler, statistics, false);
            connectVisualization (_crawler, logger, true);
        }

        crawler = _crawler;

        // set all window titles
        String name = crawler.getName ();
        if (workbenchFrame != null)
            workbenchFrame.setTitle ("Crawler Workbench: " + name);
        if (vizFrame != null)
            vizFrame.setTitle ("Visualization: " + name);

        // set configuration
        
        if (advancedMode) {
            crawlerEditor.setCrawler (crawler);
            classifierListEditor.setCrawler (crawler);
            downloadParametersEditor.setDownloadParameters (crawler.getDownloadParameters ());
            if (advancedMode) {
                linkPredicateEditor.setLinkPredicate (crawler.getLinkPredicate ());
                pagePredicateEditor.setPagePredicate (crawler.getPagePredicate ());
                actionEditor.setAction (crawler.getAction ());
            }
        }
        else
            simpleCrawlerEditor.setCrawler (crawler);
            
        if (advancedMode)
            showAdvancedTabs ();
        else
            showSimpleTabs ();
    }
    
    public Crawler getCrawler () {
        return crawler;
    }


    private void showAdvancedTabs () {
        if (configPanel.countTabs () != 5) {
            configPanel.removeAllTabPanels ();
            configPanel.addTabPanel ("Crawl", true, crawlPanel);
            configPanel.addTabPanel ("Links", true, linksPanel);
            configPanel.addTabPanel ("Pages", true, actionPanel);
            configPanel.addTabPanel ("Classifiers", true, classifiersPanel);
            configPanel.addTabPanel ("Limits", true, limitsPanel);
        }
    }

    private void showSimpleTabs () {
        if (configPanel.countTabs () != 1) {
            configPanel.removeAllTabPanels ();
            configPanel.addTabPanel ("Crawl", true, simplePanel);
        }
    }        

    /* * * * * * * * * * * * * * * * * * * * * * *
     *   Running the crawler
     * * * * * * * * * * * * * * * * * * * * * * */
            
    public void start () {
        configureCrawler ();

        if (crawler.getState () == CrawlEvent.STOPPED)
            crawler.clear ();

        Thread thread = new Thread (crawler, crawler.getName ());
        thread.setDaemon (true);
        thread.start ();
    }
    
    public void stop () {
        crawler.stop ();
    }
    
    public void pause () {
        crawler.pause ();
    }
    
    public void clear () {
        crawler.clear ();
    }

    /**
     * Notify that the crawler started
     */
    public void started (CrawlEvent event) {
        enableButtons (false, true, true, false);
    }

    /**
     * Notify that the crawler ran out of links to crawl
     */
    public void stopped (CrawlEvent event) {
        enableButtons (true, false, false, true);
    }

    /**
     * Notify that the crawler's state was cleared.
     */
    public void cleared (CrawlEvent event) {
        enableButtons (true, false, false, false);
    }

    /**
     * Notify that the crawler timed out.
     */
    public void timedOut (CrawlEvent event) {
        enableButtons (true, false, false, true);
    }

    /**
     * Notify that the crawler was paused.
     */
    public void paused (CrawlEvent event) {
        enableButtons (true, false, true, true);
    }
        
    public static void main (String[] args) throws Exception {
        Workbench w = (args.length == 0)
            ? new Workbench ()
            : new Workbench (args[0]);
        w.setAllowExit (true);

        Frame f = w.makeFrame ();
        f.show ();
    }
}

class WorkbenchFrame extends ClosableFrame
{
    Workbench workbench;

    public WorkbenchFrame (Workbench workbench) {
        super ();
        this.workbench = workbench;
    }
    
    public void close () {
        workbench.close ();
    }

    public boolean handleEvent (Event event) {
        if (workbench.doEvent (event))
            return true;
        else
            return super.handleEvent (event);
    }
}

class WorkbenchVizFrame extends ClosableFrame
{
    Workbench workbench;

    public WorkbenchVizFrame (Workbench workbench) {
        super (true);
        this.workbench = workbench;
    }
    
    public void close () {
        workbench.dockVisualizations ();
        super.close ();
    }

    public boolean handleEvent (Event event) {
        if (workbench.doEvent (event))
            return true;
        else
            return super.handleEvent (event);
    }
}

class WorkbenchTabPanel extends TabPanel {
    Button advancedButton;

    public WorkbenchTabPanel () {
        super ();
        add (advancedButton = new Button ("Advanced >>"));
    }
}

class WorkbenchVizPanel extends TabPanel {
    Workbench workbench;
    Button optionsButton;
    Button tearoffButton;

    public WorkbenchVizPanel (Workbench workbench) {
        this.workbench = workbench;
        add (optionsButton = new Button ("Options..."));
        add (tearoffButton = new Button ("Tear Off"));
    }

    public void select (int num) {
        Component prior = getSelectedComponent ();

        super.select (num);

        Component now = getSelectedComponent ();

        if (prior == now)
            return;

        if (prior != null)
            workbench.hideVisualization (prior);

        if (now != null) {
            workbench.showVisualization (now);
            now.requestFocus ();
        }
    }
}

