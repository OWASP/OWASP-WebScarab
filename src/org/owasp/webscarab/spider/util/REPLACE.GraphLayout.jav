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
package org.owasp.webscarab.spider.util; // but no dependencies on websphinx.workbench!

// Daniel Tunkelang's graph-drawing packages
import graph.*; 
import gd.*;

import java.util.*;
import java.awt.*;
import java.awt.image.ImageObserver;

public class GraphLayout extends Canvas implements Runnable, ImageObserver {

    Graph graph;   // graph to display

    double restLength = 50;       // default rest length of an edge
    double springConstant = 100;  // attraction between connected nodes
    double nodeCharge = 10000;    // repulsion between any pair of nodes

    GDAlgorithm algorithm;     // algorithm used for automatic graph layout

    boolean running = false;   // is repaint thread running?
    boolean automaticLayout = true; // is automatic graph layout enabled?
    double threshold = 100;    // if an iteration shows less "improvement" than
                               // this threshold, stop iterating
    boolean quiescent = true;  // is the graph stable?
    boolean dirty = true;      // do we need to repaint?

    int interval = 100;        // milliseconds between repaints
    int iterations = 3;        // number of layout iterations per repaint

    Color nodeColor = Color.pink;   // default background color for a node
                                    // (node label text is in Foreground color)
    Color edgeColor = Color.black;  // default color of an edge line 
    Color tipColor = Color.yellow;  // background color of a popup tip

    //RenderedNode selectedNode = null;   // currently selected node, or null
    //RenderedEdge selectedEdge = null;   // currently selected edge, or null
        // invariant: selectedNode==null || selectedEdge == null

    Object tipObject = null;       // node or edge currently under mouse, or null
    MultiLineString tip = null;    // tip string displayed for tipObject, or null
    int tipX, tipY, tipWidth, tipHeight;    // bounding box of tip

    GraphLayoutControlPanel controlPanel;

    /**
     * Make a GraphLayout.
     */
    public GraphLayout () {
        graph = new Graph ();
        resetAlgorithm ();
        start ();
    }
    
    /**
     * Erase the graph.
     */
    public synchronized void clear () {
        graph = new Graph ();
        changedGraph ();
    }

    /**
     * Get the graph.
     */
    public synchronized Graph getGraph () {
        return graph;
    }

    /**
     * Set the graph.
     */
    public synchronized void setGraph (Graph graph) {
        this.graph = graph;
        //selectedNode = null;
        //selectedEdge = null;
        tipObject = null;
        tip = null;
        changedGraph ();
    }

    /**
     * Get the graph-drawing algorithm in use.
     */
    public synchronized GDAlgorithm getAlgorithm () {
        return algorithm;
    }

    /**
     * Set the graph-drawing algorithm.
     */
    public synchronized void setAlgorithm (GDAlgorithm algorithm) {
        this.algorithm = algorithm;
        changedGraph ();
    }

    synchronized void resetAlgorithm () {
        algorithm = new AllPairsAlgorithm (springConstant, nodeCharge);
        changedGraph ();
    }

    /**
     * Get the default rest length for new edges.
     */
    public synchronized double getRestLength () {
        return restLength;
    }

    /**
     * Set the default rest length for new edges.
     */
    public synchronized void setRestLength (double restLength) {
        this.restLength = restLength;
        changedGraph ();
    }

    /**
     * Get the spring constant.
     */
    public synchronized double getSpringConstant () {
        return springConstant;
    }

    /**
     * Set the spring constant.
     */
    public synchronized void setSpringConstant (double springConstant) {
        this.springConstant = springConstant;
        resetAlgorithm ();
    }

    /**
     * Get the node charge.
     */
    public synchronized double getNodeCharge () {
        return nodeCharge;
    }

    /**
     * Set the node charge.
     */
    public synchronized void setNodeCharge (double nodeCharge) {
        this.nodeCharge = nodeCharge;
        resetAlgorithm ();
    }

    /**
     * Get the refresh interval (measured in seconds).
     */
    public synchronized int getInterval () {
        return interval;
    }

    /**
     * Set the refresh interval (in seconds).
     */
    public synchronized void setInterval (int interval) {
        this.interval = interval;
    }

    /**
     * Get the layout algorithm iterations per refresh.
     */
    public synchronized int getIterations () {
        return iterations;
    }

    /**
     * Set the layout algorithm iterations per refresh.
     */
    public synchronized void setIterations (int iterations) {
        this.iterations = iterations;
    }

    /**
     * Test whether the graph is laid out automatically.
     */
    public synchronized boolean getAutomaticLayout () {
        return automaticLayout;
    }

    /**
     * Set whether the graph is laid out automatically.
     */
    public synchronized void setAutomaticLayout (boolean f) {
        automaticLayout = f;
        quiescent = !automaticLayout;
        if (controlPanel != null)
            controlPanel.automatic.setState (automaticLayout);
    }

    /**
     * Test whether the graph is quiescent (not changing in the background).
     */
    public synchronized boolean getQuiescent () {
        return quiescent;
    }

    /**
     * Test whether the graph layout thread is running in the background
     */
    public synchronized boolean getRunning () {
        return running;
    }

    /**
     * Get the threshold.
     */
    public synchronized double getThreshold () {
        return threshold;
    }

    /**
     * Set the threshold.
     */
    public synchronized void setThreshold (double threshold) {
        this.threshold = threshold;
        changedGraph ();
    }

    /**
     * Get the node background color.
     */
    public synchronized Color getNodeColor () {
        return nodeColor;
    }

    /**
     * Set the node background color.
     */
    public synchronized void setNodeColor (Color nodeColor) {
        this.nodeColor = nodeColor;
    }

    /**
     * Get the edge color.
     */
    public synchronized Color getEdgeColor () {
        return edgeColor;
    }

    /**
     * Set the edge color.
     */
    public synchronized void setEdgeColor (Color edgeColor) {
        this.edgeColor = edgeColor;
    }

    /**
     * Get the popup tip color.
     */
    public synchronized Color getTipColor () {
        return tipColor;
    }

    /**
     * Set the popup tip color.
     */
    public synchronized void setTipColor (Color tipColor) {
        this.tipColor = tipColor;
    }

    /**
     * Get node currently under the mouse pointer, or null if no node is under the mouse.
     */
    public synchronized RenderedNode getSelectedNode () {
        return tipObject instanceof RenderedNode 
            ? (RenderedNode)tipObject
            : null;
    }

    /**
     * Get edge currently under the mouse pointer, or null if no edge is under the mouse.
     */
    public synchronized RenderedEdge getSelectedEdge () {
        return tipObject instanceof RenderedEdge 
            ? (RenderedEdge)tipObject
            : null;
    }

    /**
     * Add a node.
     */
    public synchronized void addNode (RenderedNode node) {
        graph.addNode (node);
        graph.placeNode (node, node.x, node.y);
        changedGraph ();
    }

    /**
     * Add an edge.
     */
    public synchronized void addEdge (RenderedEdge edge) {
        if (edge.restLength == 0)
            edge.restLength = restLength;
        graph.addEdge (edge);
        changedGraph ();
    }

    /**
     * Remove a node.
     */
    public synchronized void removeNode (RenderedNode node) {
        graph.removeNode (node);
        changedGraph ();
    }

    /**
     * Remove an edge.
     */
    public synchronized void removeEdge (RenderedEdge edge) {
        graph.removeEdge (edge);
        changedGraph ();
    }

    /**
     * Handle a loaded image.
     */
    public synchronized boolean imageUpdate(Image  img,
                                  int infoflags,
                                  int x,
                                  int y,
                                  int width,
                                  int height) {
        if ((infoflags & (ImageObserver.WIDTH | ImageObserver.HEIGHT)) != 0) {
            for (int i=0; i<graph.sizeNodes; ++i) {
                RenderedNode n = (RenderedNode)graph.nodes[i];
                if (n.icon == img) {
                    n.width = width;
                    n.height = height;
                    changedGraph ();
                }
            }
        }
        return super.imageUpdate (img, infoflags, x, y, width, height);
    }

    /*
     * Background thread
     *
     */

    Thread iterator;

    /**
     * Start automatic graph layout (in the background).
     */
    public synchronized void start () {
        if (!running) {
            running = true;            
            iterator = new Thread (this, "GraphListener");
            iterator.setDaemon (true);
            iterator.setPriority (Thread.MIN_PRIORITY);
            iterator.start ();
        }
    }

    /**
     * Stop automatic graph layout.
     */
    public synchronized void stop () {        
        if (running) {
            running = false;
            notify ();
            iterator = null;
        }
    }

    /**
     * The body of the background thread.  Clients should not call this
     * method.
     */
    final static int MULTIPLIER = 2;
    public synchronized void run () {
        quiescent = false;
        while (running) {
            long start = System.currentTimeMillis ();

            if (automaticLayout && !quiescent) {
                for (int i=0; i < iterations; ++i) {
                    double improvement = algorithm.improveGraph (graph);
                    dirty = true;
                    if (improvement <= threshold * graph.sizeNodes) {
                        quiescent = true;
                        break;
                    }
                }
            }

            if (dirty)
                super.repaint ();

            /*int r = (int) (System.currentTimeMillis() - start);
            int w = Math.max (interval, r * MULTIPLIER);
            System.out.println ("ran " + r + " msec, now waiting " + w + " msec");
            */

            try {
                wait (interval);
            } catch (InterruptedException e) {
            }
        }
        quiescent = true;
    }

    /**
     * Notify background thread that the graph has changed.
     */
    public synchronized void changedGraph () {
        if (automaticLayout)
            quiescent = false;
        repaint ();
    }

    /**
     * Notify background thread that the view has changed.
     */
    public synchronized void repaint () {
        if (!running)
            super.repaint ();
        else
            dirty = true;
    }

    /**
     * Show control panel for changing graph layout parameters.
     */
    public void showControlPanel () {
        if (controlPanel == null)
            controlPanel = new GraphLayoutControlPanel (this);
        controlPanel.show ();
    }

    protected void finalize () throws Throwable {
        super.finalize ();
        if (controlPanel != null) {
            controlPanel.dispose();
            controlPanel = null;
        }
    }

    /*
     * Scale coordinates from graph to screen.
     */
    double originX = 0.0, originY = 0.0;
    double scaleX = 1.0, scaleY = 1.0;

    private void scaleGraph () {
        Dimension d = size ();
        double halfScreenWidth = d.width/2.0;
        double halfScreenHeight = d.height/2.0;
        
        double sX = 1.0, sY = 1.0;
        for (int i=0; i < graph.sizeNodes; ++i) {
            RenderedNode n = (RenderedNode)graph.nodes[i];
            sX = Math.min(sX, (halfScreenWidth - n.width/2.0)/(Math.abs(n.x)+1));
            sY = Math.min(sY, (halfScreenHeight - n.height/2.0)/(Math.abs(n.y)+1));
        }
        
        double oX = halfScreenWidth;
        double oY = halfScreenHeight;
        
        for (int i=0; i < graph.sizeNodes; ++i) {
            RenderedNode n = (RenderedNode)graph.nodes[i];
            n.screenX = (int)(n.x*sX + oX);
            n.screenY = (int)(n.y*sY + oY);
        }

        // save the translation for use in placeNodeOnScreen
        originX = oX;
        originY = oY;
        scaleX = sX;
        scaleY = sY;
    }

    public synchronized void placeNodeOnScreen (RenderedNode n, int x, int y) {
        graph.placeNode (n, (x - originX)/scaleX, (y - originY)/scaleY);
        n.screenX = x;
        n.screenY = y;
    }

    public synchronized void placeNodeOnGraph (RenderedNode n, double x, double y) {
        graph.placeNode (n, x, y);
        n.screenX = (int)(x*scaleX + originX);
        n.screenY = (int)(y*scaleY + originY);
    }

    /*
     * Painting methods
     *
     */

    Image offscreen;     // offscreen drawing area
    Dimension offSize;   // size of offscreen buffer
    Graphics offg;       // drawonable associated with offscreen buffer
    FontMetrics fm;      // font metrics for offscreen buffer

    public void update (Graphics g) {
        // don't clear window with background color first
        //long before = System.currentTimeMillis ();
        paint (g);
        //long after = System.currentTimeMillis ();
        //System.out.println ("repaint: " + (after - before) + " msec");
    }

    void createOffscreenArea (Dimension d) {
        offSize = new Dimension (d.width  > 0 ? d.width : 1,
                                 d.height  > 0 ? d.height : 1);
        offscreen = createImage (offSize.width, offSize.height);
        offg = offscreen.getGraphics ();
        offg.setFont (getFont ());
        fm = offg.getFontMetrics ();
    }

    public synchronized void paint (Graphics g) {
        Dimension d = size ();

        if (offscreen == null 
            || d.width != offSize.width
            || d.height != offSize.height)
            createOffscreenArea (d);

        offg.setColor (getBackground ());
        offg.fillRect (0, 0, d.width, d.height);

        scaleGraph ();
        
        // paint the edges first
        for (int i=0; i<graph.sizeEdges; ++i) {
            RenderedEdge e = (RenderedEdge)graph.edges[i];
            if (e == null)
                continue;
            RenderedNode from = (RenderedNode)e.from;
            RenderedNode to = (RenderedNode)e.to;
            if (from == null || to == null)
                continue;
            
            Color c = e.color;
            if (c == null)
                c = edgeColor;
            
            offg.setColor (c);
            drawArrowToBox (offg, (int)from.screenX, (int)from.screenY, 
                            (int)to.screenX, (int)to.screenY, 
                            (int)(to.width/2), (int)(to.height/2),
                            6, 3, e.thick);
        }
        
        // paint the nodes on top
        for (int i=0; i < graph.sizeNodes; ++i) {
            RenderedNode n = (RenderedNode)graph.nodes[i];
            if (n == null)
                continue;
            
            int width = (int)n.width;
            int height = (int)n.height;
            int x = (int)n.screenX - width/2;
            int y = (int)n.screenY - height/2;
            Color c = n.color;
            
            if (n.icon == null) {
                if (c == null)
                    c = nodeColor;
                
                offg.setColor (c);
                offg.fillRect (x, y, width, height);
                offg.setColor (getForeground ());
                offg.drawRect (x, y, width-1, height-1);
                offg.drawString (n.name, x+5, y+2 + fm.getAscent ());
            }
            else {
                // NIY: scaling
                if (c == null)
                    offg.drawImage (n.icon, x, y, this);
                else
                    offg.drawImage (n.icon, x, y, c, this);
            }
        }
        
        // paint the tip on top
        if (tip != null) {
            offg.setColor (tipColor);
            offg.fillRect (tipX, tipY, tipWidth, tipHeight);
            offg.setColor (Color.black);
            offg.drawRect (tipX, tipY, tipWidth-1, tipHeight-1);
            tip.draw (offg, tipX + 5, tipY + 2, Label.LEFT);
        }
        
        // draw border
        offg.setColor (quiescent ? getForeground () : Color.red);
        offg.drawRect (0, 0, d.width-1, d.height-1);
        
        // copy to screen
        g.drawImage (offscreen, 0, 0, null);

        dirty = false;
    }

    void drawArrowToBox (Graphics g, int x1, int y1, int x2, int y2, 
                         int wHalfBox, int hHalfBox, 
                         int head_length, int head_width, boolean thick) {
        if (thick) {
          drawArrowToBox (g, x1, y1, x2, y2, 
                          wHalfBox, hHalfBox, head_length, head_width, false);
          drawArrowToBox (g, x1-1, y1, x2-1, y2, 
                          wHalfBox, hHalfBox, head_length, head_width, false);
          drawArrowToBox (g, x1, y1-1, x2, y2-1, 
                          wHalfBox, hHalfBox, head_length, head_width, false);
          drawArrowToBox (g, x1-1, y1-1, x2-1, y2-1, 
                          wHalfBox, hHalfBox, head_length, head_width, false);
        }
        else {
            double dx = x2 - x1;
            double dy = y2 - y1;
            double d = Math.sqrt (dx * dx + dy * dy);
            if (d < 1.0) {
                d = 1.0;
                dx = 1;
            }
            dx /= d;
            dy /= d;
            
            double lx = head_length * dx;
            double ly = head_length * dy;
            double wx = head_width * dx;
            double wy = head_width * dy;

            double cp1 = dx*hHalfBox - dy*wHalfBox;
            double cp2 = dx*hHalfBox + dy*wHalfBox;
            
            if (cp1 < 0) {
                    if (cp2 < 0) {
                        // region I
                        x2 += wHalfBox;
                        y2 += wHalfBox*dy/dx;
                    }
                    else {
                        // region II
                        y2 -= hHalfBox;
                        x2 -= hHalfBox*dx/dy;
                    }
            }
            else {
                    if (cp2 > 0) {
                        // region III
                        x2 -= wHalfBox;
                        y2 -= wHalfBox*dy/dx;
                    }
                    else {
                        // region IV
                        y2 += hHalfBox;
                        x2 += hHalfBox*dx/dy;
                    }
            }
            
            g.drawLine (x1, y1, x2, y2);
            g.drawLine (x2, y2, (int)(x2-lx+wy+0.5), (int)(y2-ly-wx+.5));
            g.drawLine (x2, y2, (int)(x2-lx-wy+0.5), (int)(y2-ly+wx+.5));
        }
    }

    public synchronized FontMetrics getFontMetrics () {
        if (fm == null) {
            Dimension d = size ();
            createOffscreenArea (d);
        }
        return fm;
    }

    // intercept font settings and transfer to offscreen buffer
    public synchronized void setFont (Font f) {
        super.setFont (f);
        if (offg != null) {
            offg.setFont (f);
            fm = offg.getFontMetrics ();
        }
    }

    /*
    public Dimension preferredSize () {
        return new Dimension (400, 400);
    }
    */
    
    /*
     * Selecting and dragging nodes
     *
     */
     
    RenderedNode dragNode = null;   // node being dragged, or null
    int dragOffsetX, dragOffsetY;   
        // initial displacement of mouse cursor from dragged object's origin;
        // the object remains at this displacement throughout the drag

    void point (int x, int y) {
        Object over = pick (x, y);
        if (over == null) {
            if (tipObject != null || tip != null) {
                tipObject = null;
                tip = null;
                super.repaint ();
            }
        }
        else if (over != tipObject) {
            String[] tipLines = ((Tipped)over).getTip ();

            if (tipLines == null) {
                tipObject = null;
                tip = null;
                super.repaint ();
            }
            else {
                tipObject = over;
                tip = new MultiLineString (tipLines);
                tipWidth = tip.getWidth (fm) + 10;
                tipHeight = tip.getHeight (fm) + 4;
                tipX = Math.max (x - tipWidth/2, 0);
                tipY = Math.min (y + 25, 
                                 offSize.height - tipHeight);
                super.repaint ();
            }
        }
    }
    
    void leave () {
        if (tipObject != null || tip != null) {
            tip = null;
            tipObject = null;
            super.repaint ();
        }
    }        
        
    void click (int x, int y, boolean rightClick) {
	    requestFocus();

        Object over = pick (x, y);
        if (over != null) {
            if (over instanceof RenderedNode) {
                RenderedNode n = (RenderedNode)over;
                //selectedNode = (RenderedNode)over;
                //selectedEdge = null;
                
                // start dragging the node
                if (!n.fixed) {
                    dragNode = n;
                    dragNode.fixed = true;
                    dragOffsetX = (int)dragNode.screenX - x;
                    dragOffsetY = (int)dragNode.screenY - y;
                }
            }
            //else {
            //    // over instanceof RenderedEdge
            //    selectedNode = null;
            //    selectedEdge = (RenderedEdge)over;
            //}
        }
        else if (rightClick) {
            // right-click over background
            showControlPanel ();
        }
    }
    
    void drag (int x, int y) {
        if (dragNode != null) {
            placeNodeOnScreen (dragNode,
                               x + dragOffsetX,
                               y + dragOffsetY);
            changedGraph ();
        }
    }        
    
    void drop (int x, int y) {
        if (dragNode != null) {
            placeNodeOnScreen (dragNode,
                               x + dragOffsetX,
                               y + dragOffsetY);
            changedGraph ();
            dragNode.fixed = false;
            dragNode = null;
        }
    }
     
    public boolean handleEvent (Event event) {
        switch (event.id) {
            case Event.MOUSE_DOWN:
                click (event.x, event.y, event.metaDown());
                return true;
            case Event.MOUSE_UP:
                drop (event.x, event.y);
                return true;
            case Event.MOUSE_MOVE:
                point (event.x, event.y);
                return true;
            case Event.MOUSE_EXIT:
                leave ();
                return true;
            case Event.MOUSE_DRAG:
                if (dragNode != null) {
                    drag (event.x, event.y);
                    return true;
                }
                else super.handleEvent (event);
            default:
                return super.handleEvent (event);
        }
    }
    
    /**
     * Find the object (Node or Edge) at position (x,y) relative to the window.
     * @param x X position
     * @param y Y position
     * @return topmost object under (x,y), or null if none
     */
    public Object pick (int x, int y) {
        // proceed in reverse display order: nodes first, then edges
        for (int i=graph.sizeNodes-1; i >= 0; --i) {
            RenderedNode n = (RenderedNode)graph.nodes[i];
            if (Math.abs (n.screenX - x) < n.width/2 && Math.abs (n.screenY - y) < n.height/2)
                return n;
        }
        
        for (int i=graph.sizeEdges-1; i>=0; --i) {
            RenderedEdge e = (RenderedEdge)graph.edges[i];
            RenderedNode to = (RenderedNode)e.to;
            RenderedNode from = (RenderedNode)e.from;
            if (inLineSegment (x, y, 
                               (int)to.screenX, (int)to.screenY,
                               (int)from.screenX, (int)from.screenY, 4))
                return e;
        }
        
        return null;
    }
    
    boolean inLineSegment (int x, int y, int x1, int y1, int x2, int y2,
                           int threshold) {
        int left, right, top, bottom;
        if (x1 < x2) {
            left = x1; right = x2;
        }
        else {
            left = x2; right = x1;
        }
        if (y1 < y2) {
            top = y1; bottom = y2;
        }
        else {
            top = y2; bottom = y1;
        }

        // check bounding box first
        if (x < left-threshold || x > right+threshold ||
            y < top-threshold || y > bottom+threshold) {
            return false;
        }

        // equation for line is ax + by + c = 0
        // d/sqrt(a^2+b^2) is the distance between line and point <x,y>
        int a = y1 - y2;
        int b = x2 - x1;
        int c = x1*y2 - x2*y1;
        int d = a*x + b*y + c;

        return (d*d <= threshold * threshold * (a*a + b*b));
    }
 
    /*
     * Testing
     *
    public static void main (String[] args) {
        Frame f = new Frame ();
        f.addWindowListener (new WindowAdapter () {
            public void windowClosing (WindowEvent event) {
                ((Frame)event.getSource()).dispose();
            }
        });
        f.setSize (100,100);
        f.setLayout (new BorderLayout ());
        
        GraphLayout g = new GraphLayout ();
        f.add ("Center", g);
        f.show ();
        
        Node last = null;
        for (int i=0; i<args.length; ++i) {
            try {
                Thread.sleep (200);
            } catch (InterruptedException e) {}
            RenderedNode n = new RenderedNode();
            n.name = args[i];
            g.addNode (n);
            g.graph.placeNode (n, 0, 0);
            
            if (last != null) {
                RenderedEdge e = new RenderedEdge (last, n);
                g.addEdge (e);
            }
                
        }
    }
    */
}

class GraphLayoutControlPanel extends ClosableFrame {
    GraphLayout gl;

    Checkbox automatic;

    Scrollbar threshold;
    Scrollbar restLength;
    Scrollbar springConstant;
    Scrollbar nodeCharge;

    TextField thresholdText;
    TextField restLengthText;
    TextField springConstantText;
    TextField nodeChargeText;

    public GraphLayoutControlPanel (GraphLayout graphLayout) {
        super ("Graph Layout Control Panel", true);
        gl = graphLayout;

        setLayout (new GridBagLayout ());
        Constrain.add (this, automatic = new Checkbox ("Automatic layout"),
                       Constrain.labelLike (0, 0, 2));
        automatic.setState (true);
        Constrain.add (this, new Label ("Threshold:", Label.LEFT), Constrain.labelLike (0,1));
        Constrain.add (this, thresholdText = new TextField (String.valueOf (gl.getThreshold())),
                       Constrain.fieldLike (1,1));
        Constrain.add (this, threshold = new Scrollbar (Scrollbar.HORIZONTAL,
                                        (int)gl.getThreshold(), 50, 0, 1000),
                                        Constrain.fieldLike (0,2,2));
        Constrain.add (this, new Label ("Rest length:", Label.LEFT), Constrain.labelLike (0,3));
        Constrain.add (this, restLengthText = new TextField (String.valueOf (gl.getRestLength())),
                       Constrain.fieldLike (1,3));
        Constrain.add (this, restLength = new Scrollbar (Scrollbar.HORIZONTAL,
                                         (int)gl.getRestLength(), 50, 0, 1000), Constrain.fieldLike (0,4,2));
        Constrain.add (this, new Label ("Spring constant:", Label.LEFT), Constrain.labelLike (0,5));
        Constrain.add (this, springConstantText = new TextField (String.valueOf (gl.getSpringConstant())),
                       Constrain.fieldLike (1,5));
        Constrain.add (this, springConstant = new Scrollbar (Scrollbar.HORIZONTAL,
                                         (int)gl.getSpringConstant(), 50, 0, 1000), Constrain.fieldLike (0,6,2));
        Constrain.add (this, new Label ("Node charge:", Label.LEFT), Constrain.labelLike (0,7));
        Constrain.add (this, nodeChargeText = new TextField (String.valueOf (Math.sqrt(gl.getNodeCharge()))),
                       Constrain.fieldLike (1,7));
        Constrain.add (this, nodeCharge = new Scrollbar (Scrollbar.HORIZONTAL,
                                         (int)(Math.sqrt(gl.getNodeCharge())), 50, 0, 1000), Constrain.fieldLike (0,8,2));
        pack ();
    }
    
    public boolean handleEvent (Event event) {
        // FIX: doesn't support text entry
        if (event.target == automatic)
            gl.setAutomaticLayout (automatic.getState ());
        else if (event.target == threshold)
            gl.setThreshold (((Integer)event.arg).intValue());
        else if (event.target == restLength)
            gl.setRestLength (((Integer)event.arg).intValue());
        else if (event.target == springConstant)
            gl.setSpringConstant (((Integer)event.arg).intValue());
        else if (event.target == restLength) {
            int v = ((Integer)event.arg).intValue();
            gl.setNodeCharge (v*v);
        }
        else
            return super.handleEvent (event);
        return true;
    }
}
