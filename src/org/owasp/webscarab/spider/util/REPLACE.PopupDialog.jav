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
package org.owasp.webscarab.spider.util;

import java.awt.*;
import java.util.Vector;

// Note: after creating a PopupDialog (like any other top-level window, it
// seems), the JDK 1.1 runtime won't exit by itself, even if the PopupDialog
// is properly disposed.  Need to force it to exit using System.exit().

public class PopupDialog extends Dialog {

    public static final int YES = 0;
    public static final int OK = 0;
    public static final int NO = 1;
    public static final int CANCEL = 2;

    Frame parent;
    int answer = -1;
    String text;
    
    TextField textfield;
    Button okButton, noButton, cancelButton;

    public static String ask (Component comp, String topic, String question, String defaultAnswer) {
        PopupDialog d = new PopupDialog (getFrame (comp), topic, true, 
                                         question, defaultAnswer, 
                                         "OK", null, "Cancel");
        d.show ();
        switch (d.getAnswer ()) {
            case OK:
                return d.getText ();
            default:
                return null;
        }
    }

    public static String ask (Component comp, String topic, String question) {
        return ask (comp, topic, question, "");
    }

    public static boolean okcancel (Component comp, String topic, String question) {
        PopupDialog d = new PopupDialog (getFrame (comp), topic, true, 
                                         question, null,
                                         "OK", null, "Cancel");
        d.show ();
        return (d.getAnswer () == OK);
    }

    public static int yesnocancel (Component comp, String topic, String question) {
        PopupDialog d = new PopupDialog (getFrame (comp), topic, true,
                                         question, null,
                                         "Yes", "No", "Cancel");
        d.show ();
        return d.getAnswer ();
    }

    public static void warn (Component comp, String topic, String message) {
        PopupDialog d = new PopupDialog (getFrame (comp), topic, true,
                                         message, null,
                                         "OK", null, null);
        d.show ();
    }

    public static String askFilename (Component comp, String topic, 
                                  String defaultFilename, boolean loading) {
        try {
            FileDialog fd = new FileDialog (PopupDialog.getFrame(comp),
                                            topic, 
                                            loading ? FileDialog.LOAD : FileDialog.SAVE);
            fd.show ();
            String dir = fd.getDirectory();
            String file = fd.getFile ();
            if (dir == null || file == null)
                return null;
            else
                return dir + file;
        } catch (AWTError e) {
            return ask (comp, topic, "Filename:", defaultFilename);
        }
    }


    public static Frame getFrame (Component comp) {
        for (; comp!=null; comp = comp.getParent ())
            if (comp instanceof Frame)
                return (Frame)comp;
        return null;
    }

    public PopupDialog (Frame parent, String title, boolean modal) {
        super (parent, title, modal);
        this.parent = parent;
    }
    public PopupDialog (Frame parent, String title, boolean modal,
                         String question, String initialEntry,
                         String okOrYes, String no, String cancel) {
        this (parent != null ? parent : new Frame (), title, modal);

        System.err.println (question);
        setFont (this.parent.getFont ());

        Panel middle = new Panel ();
        add ("Center", BorderPanel.wrap (middle, 10, 10, 10, 5));
        middle.setLayout (new BorderLayout ());
        MultiLineLabel questionLabel = new MultiLineLabel (question, Label.LEFT);
        middle.add ("Center", questionLabel);
        if (initialEntry != null) {
            textfield = new TextField (Math.max (40, initialEntry.length()+1));
            middle.add ("South", textfield);
            textfield.setText (initialEntry);
            textfield.selectAll ();
        }

        Panel bottom = new Panel ();
        add ("South", bottom);

        okButton = new Button (okOrYes);
        bottom.add (okButton);
        if (no != null) {
            noButton = new Button (no);
            bottom.add (noButton);
        }

        if (cancel != null) {
            cancelButton = new Button (cancel);
            bottom.add (cancelButton);
        }

//         if (System.getProperty ("java.vendor").startsWith ("Netscape")) {
//             // pack() doesn't work under Netscape!
//             Dimension d = questionLabel.preferredSize();
//             resize (Math.max (100, d.width), 100 + d.height);
//         }
//         else 
        pack ();
    }

    public void show () {
        Dimension size = size();
        Dimension parentSize = parent != null ? parent.size() : Toolkit.getDefaultToolkit().getScreenSize();
        
        if (parentSize != null 
            && parentSize.width != 0  && parentSize.height != 0) {
            int x = (parentSize.width - size.width) / 2;
            int y = (parentSize.height - size.height) / 2;
            move (x, y);
        }

        super.show ();
        if (textfield != null)
            textfield.requestFocus ();
    }
    
    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target == okButton) {
                answer = OK;
                close ();
            }
            else if (event.target == noButton) {
                answer = NO;
                close ();
            }
            else if (event.target == cancelButton) {
                answer = CANCEL;
                close ();
            }
            else if (event.target == textfield) {
                answer = OK;
                close ();
            }
            else
                return super.handleEvent (event);
        }
        else if (event.id == Event.WINDOW_DESTROY) {
            if (cancelButton != null) {
                answer = CANCEL;
                close ();
            }
            else if (noButton == null && cancelButton == null) {
                answer = OK;
                close ();
            }
            else
                return super.handleEvent (event);
        }
        else
            return super.handleEvent (event);
            
        return true;
    }

    public int getAnswer () {
        return answer;
    }
    
    public String getText () {
        return text;
    }

    Vector listeners = new Vector ();

    public synchronized void addPopupListener (PopupListener listener) {
        listeners.addElement (listener);
    }

    public synchronized void removePopupListener (PopupListener listener) {
        listeners.removeElement (listener);
    }

    public synchronized void close () {
        text = (answer == OK && textfield != null) 
                 ? textfield.getText () : null;
                 
        dispose ();
        if (parent == null)
            ((Frame)getParent()).dispose ();
        else
            parent.requestFocus ();

        if (answer != -1) {
            PopupEvent e = new PopupEvent (answer, text);
            for (int i=0; i<listeners.size (); ++i) {
                PopupListener p = (PopupListener) (listeners.elementAt (i));
                switch (e.getID ()) {
                    case YES:
                        p.yes (e);
                        break;
                    case NO:
                        p.no (e);
                        break;
                    case CANCEL:
                        p.cancel (e);
                        break;
                }
            }
        }
        
        try {
            finalize ();
        } catch (Throwable t) {
            throw new RuntimeException (t.toString());
        }
    }
    
    
    /*
     * Testing
     *
     */
    public static void main (String[] args) {
        String name = ask (null, "Enter Name", "Enter your full name:");
        
        if (name != null) {
            switch (yesnocancel (null, "Confirm", 
                                 "Hello, " + name + ".\nIs this your name?")) {
                case PopupDialog.YES:
                    if (okcancel (null, "Thanks", 
                                  "Great!\nDo you want to play a game?")) {
                        warn (null, "Sorry", "Too bad, my mommy won't let me out of the house.");
                    }
                    break;
                    
                case PopupDialog.NO:
                    warn (null, "D'oh", "Oops.  My bad.");
                    break;
            }
        }

        Runtime.runFinalizersOnExit (true);
        System.exit (0);
    }

}
