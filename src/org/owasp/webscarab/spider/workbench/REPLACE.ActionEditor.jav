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
import websphinx.*;
import websphinx.util.Constrain;
import websphinx.util.PopupDialog;

// FIX: consider implementing java.beans.PropertyEditor
public class ActionEditor extends Panel { 

    ActionFeatureChoice choice;

    /**
     * Make a ActionEditor.
     */
    public ActionEditor () {
        setLayout (new GridBagLayout ());
        choice = new ActionFeatureChoice ();
        Constrain.add (this, choice, Constrain.labelLike (0, 0));
        Constrain.add (this, choice.getArgs(), Constrain.areaLike (0, 1));
        setAction (null);
    }

    public void setAction (Action act) {
        choice.setAction (act);
    }

    public Action getAction () {
        return choice.getAction ();
    }

}

class ActionFeatureChoice extends FeatureChoice {
    ActionFeatureArgs args = new ActionFeatureArgs ();

    final static String NULL_ACTION = "none";
    final static String HIGHLIGHT_ACTION = "highlight";
    final static String MIRROR_ACTION = "save";
    final static String CONCAT_ACTION = "concatenate";
    final static String EXTRACT_ACTION = "extract";
    final static String SCRIPT_ACTION = "script";

    public ActionFeatureChoice () {
        addItem (NULL_ACTION);
        addItem (MIRROR_ACTION);
        addItem (CONCAT_ACTION);
        addItem (EXTRACT_ACTION);
        addItem (HIGHLIGHT_ACTION);
        addItem (SCRIPT_ACTION);
    }
    
    public void setAction (Action act) {
        if (act == null) {
            select (NULL_ACTION);
        }
        else if (act instanceof HighlightAction) {
            HighlightAction highlight = (HighlightAction)act;
            select (HIGHLIGHT_ACTION);
            args.setColor (highlight.getColor ());
            args.setScale (highlight.getScale ());
            args.setIcon (highlight.getIcon ());
        }
        else if (act instanceof MirrorAction) {
            MirrorAction mirror = (MirrorAction)act;
            select (MIRROR_ACTION);
            args.setMirrorDirectory (mirror.getDirectory ());
            args.setMirrorUseBrowser (mirror.getUseBrowser ());
        }
        else if (act instanceof ConcatAction) {
            ConcatAction concat = (ConcatAction)act;
            select (CONCAT_ACTION);
            args.setConcatFilename (concat.getFilename ());
            args.setConcatUseBrowser (concat.getUseBrowser ());
            args.prolog = concat.prolog != null ? concat.prolog : Concatenator.defaultProlog;
            args.header = concat.header != null ? concat.header : Concatenator.defaultHeader;
            args.footer = concat.footer != null ? concat.footer : Concatenator.defaultFooter;
            args.divider = concat.divider != null ? concat.divider : Concatenator.defaultDivider;
            args.epilog = concat.epilog != null ? concat.epilog : Concatenator.defaultEpilog;
        }
        else if (act instanceof ExtractAction) {
            ExtractAction extract = (ExtractAction)act;
            select (EXTRACT_ACTION);
            args.setExtractFilename (extract.getFilename ());
            args.setExtractUseBrowser (extract.getUseBrowser ());
            args.setExtractPattern (extract.getPattern ().toString ());
            args.setTextOnly (extract.getTextOnly ());
        }
        else if (act instanceof Script) {
            Script script = (Script)act;
            select (SCRIPT_ACTION);
            args.setScript (script.getScript ());
        }
        else {
            select (NULL_ACTION);
        }
    }

    public Panel getArgs () {
        return args;
    }

    public Action getAction () {
        String actn = getSelectedItem ();
        if (actn.equals (HIGHLIGHT_ACTION))
            return new HighlightAction (args.getColor (),
                                        args.getScale (),
                                        args.getIcon ());
        else if (actn.equals (MIRROR_ACTION))
            return new MirrorAction (args.getMirrorDirectory (),
                                     args.getMirrorUseBrowser ());
        else if (actn.equals (CONCAT_ACTION))
            return new ConcatAction (args.getConcatFilename (),
                                     args.getConcatUseBrowser (),
                                     args.prolog, args.header, args.footer,
                                     args.divider, args.epilog);
        else if (actn.equals (EXTRACT_ACTION))
            return new ExtractAction (new TagExp (args.getExtractPattern()),
                                      args.getExtractUseBrowser (),
                                      args.getExtractFilename (),
                                      args.getTextOnly ());
        else if (actn.equals (SCRIPT_ACTION))
            return new Script (args.getScript (), false);
        else
            return null;
    }
}

class ActionFeatureArgs extends Panel {

    static final String TEMPORARY_DIR = "(temporary directory)";
    static final String TEMPORARY_FILE = "(temporary file)";

    Choice color;
    Choice scale;
    //Choice icon;        
    TextField mirrorDirectory;    
    Checkbox mirrorUseBrowser;

    TextField concatFilename;
    Checkbox concatUseBrowser;
    Button optionsButton;
    String prolog = Concatenator.defaultProlog;
    String header = Concatenator.defaultHeader;
    String footer = Concatenator.defaultFooter;
    String divider = Concatenator.defaultDivider;
    String epilog = Concatenator.defaultEpilog;

    TextField extractFilename;
    TextArea extractPattern;
    Choice extractMedium;
    Checkbox extractUseBrowser;

    TextArea script;

    Button browseMirrorDirectory;
    Button browseConcatFilename;
    Button browseExtractFilename;

    public ActionFeatureArgs () {
        Panel panel;

        setLayout (new CardLayout ());

        add (ActionFeatureChoice.NULL_ACTION, panel = new Panel ());

        add (ActionFeatureChoice.HIGHLIGHT_ACTION, panel = Constrain.makeConstrainedPanel (4, 1));
        Constrain.add (panel, new Label (" with color "), Constrain.labelLike (0, 0));
        Constrain.add (panel, color = new Choice (), Constrain.fieldLike (1, 0));
		color.addItem ("black");
		color.addItem ("blue");
		color.addItem ("cyan");
		color.addItem ("green");
		color.addItem ("magenta");
		color.addItem ("orange");
		color.addItem ("pink");
		color.addItem ("red");
		color.addItem ("white");
		color.addItem ("yellow");
		color.select ("blue");
		scale = new Choice ();
        /*Constrain.add (panel, new Label (" and scale "), Constrain.labelLike (2, 0));
        Constrain.add (panel, scale, Constrain.fieldLike (3, 0));
        scale.addItem ("small");
        scale.addItem ("normal");
        scale.addItem ("large");
        scale.select ("normal");*/
        // NIY: icon
        //Constrain.add (panel, new Label (" and icon "), Constrain.labelLike (4, 0));
        //Constrain.add (panel, icon = new Choice (), Constrain.fieldLike (5, 0));
        
        add (ActionFeatureChoice.MIRROR_ACTION, panel = Constrain.makeConstrainedPanel (3, 2));
        Constrain.add (panel, new Label ("to directory: "), Constrain.labelLike (0, 0));
        Constrain.add (panel, mirrorDirectory = new TextField(), Constrain.fieldLike (1, 0));
        Constrain.add (panel, browseMirrorDirectory = new Button ("..."), Constrain.labelLike (2, 0));
        mirrorUseBrowser = new Checkbox ("Display directory in browser");
        mirrorUseBrowser.setState (true);
        if (Context.getBrowser() != null) {
            mirrorDirectory.setText (TEMPORARY_DIR);
            Constrain.add (panel, mirrorUseBrowser, Constrain.labelLike (1, 1));
        }
            
        add (ActionFeatureChoice.CONCAT_ACTION, panel = Constrain.makeConstrainedPanel (4, 2));
        Constrain.add (panel, new Label ("to file: "), Constrain.labelLike (0, 0));
        Constrain.add (panel, concatFilename = new TextField(), Constrain.fieldLike (1, 0, 2));
        Constrain.add (panel, browseConcatFilename = new Button ("..."), Constrain.labelLike (3, 0));
        concatUseBrowser = new Checkbox ("Display in browser");
        concatUseBrowser.setState (true);
        if (Context.getBrowser() != null) {
            concatFilename.setText (TEMPORARY_FILE);
            Constrain.add (panel, concatUseBrowser, Constrain.labelLike (1, 1));
        }
        Constrain.add (panel, optionsButton = new Button ("Options..."),
                       Constrain.labelLike (2, 1));
        
        add (ActionFeatureChoice.EXTRACT_ACTION, panel = Constrain.makeConstrainedPanel (5, 4));
        Constrain.add (panel, new Label ("regions matching the HTML tag expression:"), Constrain.labelLike (0, 0, 5));
        Constrain.add (panel, extractPattern = new TextArea(3, 40), Constrain.fieldLike (0, 1, 5));
        Constrain.add (panel, new Label ("as"), Constrain.labelLike (0, 2));
        Constrain.add (panel, extractMedium = new Choice (), Constrain.labelLike (1, 2));
        extractMedium.addItem ("HTML");
        extractMedium.addItem ("text");
        Constrain.add (panel, new Label ("to file: "), Constrain.labelLike (2, 2));
        Constrain.add (panel, extractFilename = new TextField(), Constrain.fieldLike (3, 2));
        Constrain.add (panel, browseExtractFilename = new Button ("..."), Constrain.labelLike (4, 2));
        extractUseBrowser = new Checkbox ("Display in browser");
        extractUseBrowser.setState (true);
        if (Context.getBrowser() != null) {
            extractFilename.setText (TEMPORARY_FILE);
            Constrain.add (panel, extractUseBrowser, Constrain.labelLike (3, 3));
        }
            
        ScriptInterpreter interp = Context.getScriptInterpreter ();

        script = new TextArea (4,40);
        if (interp != null) {
            add (ActionFeatureChoice.SCRIPT_ACTION, 
                 panel = Constrain.makeConstrainedPanel (1, 2));
            Constrain.add (panel, new Label (interp.getLanguage() + " Function (crawler, page)"), 
                           Constrain.labelLike (0, 0));
            Constrain.add (panel, script, Constrain.areaLike (0, 1));
        }
        else {
            add (ActionFeatureChoice.SCRIPT_ACTION, 
                 panel = Constrain.makeConstrainedPanel (1, 1));
            Constrain.add (panel, new Label ("No scripting language is available."),
                           Constrain.labelLike (0, 0));
        }
    }
    
    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target == browseMirrorDirectory)
                browse ("Save Pages in Directory", mirrorDirectory);
            else if (event.target == browseConcatFilename)
                browse ("Save Concatenation As", concatFilename);
            else if (event.target == browseExtractFilename)
                browse ("Save Extracts As", extractFilename);
            else if (event.target == optionsButton)
                new ConcatOptions(this).show ();
            else
                return super.handleEvent (event);
        }
        else
            return super.handleEvent (event);
            
        return true;
    }
        
    
    void browse (String title, TextField target) {
        String fn = PopupDialog.askFilename (this, title, target.getText(), false);
        if (fn != null)
            target.setText (fn);
    }
                       
    public void setColor (String color) {
        this.color.select (color);
    }

    public String getColor () {
        return color.getSelectedItem ();
    }

    public void setScale (String scale) {
        try {
            double d = Double.valueOf (scale).doubleValue();
            // FIX: allow user to enter any scale factor ?
            if (d < 1)
                this.scale.select ("small");
            else if (d > 1)
                this.scale.select ("large");
            else
                this.scale.select ("normal");
        } catch (NumberFormatException e) {
            this.scale.select ("normal");                
        }
    }

    public String getScale () {
        switch (scale.getSelectedIndex()) {
            case 0: return "0.5";
            case 2: return "2.0";
            default: return "1.0";
        }
    }

    public void setIcon (String icon) {
        //this.icon.select (color);
    }

    public String getIcon () {
        return null;
        //return icon.getSelectedItem ();
    }

    
    public void setMirrorDirectory (String directory) {
        mirrorDirectory.setText (directory != null ? directory : TEMPORARY_DIR);
    }

    public String getMirrorDirectory () {
        String f = mirrorDirectory.getText ();
        return f.equals (TEMPORARY_DIR) ? null : f;
    }

    public void setMirrorUseBrowser (boolean use) {
        mirrorUseBrowser.setState (use);
    }

    public boolean getMirrorUseBrowser () {
        return mirrorUseBrowser.getState ();
    }

    public void setConcatFilename (String filename) {
        concatFilename.setText (filename != null ? filename : TEMPORARY_FILE);
    }

    public String getConcatFilename () {
        String f = concatFilename.getText ();
        return f.equals (TEMPORARY_FILE) ? null : f;
    }

    public void setConcatUseBrowser (boolean use) {
        concatUseBrowser.setState (use);
    }

    public boolean getConcatUseBrowser () {
        return concatUseBrowser.getState ();
    }

    public void setExtractFilename (String filename) {
        extractFilename.setText (filename != null ? filename : TEMPORARY_FILE);
    }

    public String getExtractFilename () {
        String f = extractFilename.getText ();
        return f.equals (TEMPORARY_FILE) ? null : f;
    }

    public void setExtractUseBrowser (boolean use) {
        extractUseBrowser.setState (use);
    }

    public boolean getExtractUseBrowser () {
        return extractUseBrowser.getState ();
    }

    public void setExtractPattern (String pattern) {
        extractPattern.setText (pattern);
    }

    public String getExtractPattern () {
        return extractPattern.getText ();
    }
    
    public void setTextOnly (boolean f) {
        extractMedium.select (f ? "text" : "HTML");
    }
    
    public boolean getTextOnly () {
        return extractMedium.getSelectedItem().equals ("text");
    }

    public void setScript (String script) {
        this.script.setText (script);
    }

    public String getScript () {
        return script.getText ();
    }
}

class ConcatOptions extends PopupDialog {
    ActionFeatureArgs e;

    TextArea prolog, header, footer, divider, epilog;
    
    Button applyButton;
    Button okButton;
    Button cancelButton;

    public ConcatOptions (ActionFeatureArgs e) {
        super (getFrame (e), "Concatenate Options", true);
        this.e = e;

        setLayout (new GridBagLayout ());

        Constrain.add (this, new Label ("Prolog:"),
                       Constrain.labelLike (0, 0));
        Constrain.add (this, prolog = new TextArea (e.prolog, 3, 40),
                       Constrain.areaLike (1, 0));

        Constrain.add (this, new Label ("Page Header:"),
                       Constrain.labelLike (0, 1));
        Constrain.add (this, header = new TextArea (e.header, 3, 40),
                       Constrain.areaLike (1, 1));

        Constrain.add (this, new Label ("Page Footer:"),
                       Constrain.labelLike (0, 2));
        Constrain.add (this, footer = new TextArea (e.footer, 3, 40),
                       Constrain.areaLike (1, 2));

        Constrain.add (this, new Label ("Page Divider:"),
                       Constrain.labelLike (0, 3));
        Constrain.add (this, divider = new TextArea (e.divider, 3, 40),
                       Constrain.areaLike (1, 3));

        Constrain.add (this, new Label ("Epilog:"),
                       Constrain.labelLike (0, 4));
        Constrain.add (this, epilog = new TextArea (e.epilog, 3, 40),
                       Constrain.areaLike (1, 4));

        Panel panel;    
        Constrain.add (this, panel = new Panel(), 
                       Constrain.centered (Constrain.labelLike (0, 5, 2)));
        panel.add (applyButton = new Button ("Apply"));
        panel.add (okButton = new Button ("OK"));
        panel.add (cancelButton = new Button ("Cancel"));

        pack ();
    }

    void writeBack () {
        e.prolog = prolog.getText();
        e.header = header.getText();
        e.footer = footer.getText();
        e.divider = divider.getText();
        e.epilog = epilog.getText();
    }
    
    
    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target == applyButton)
                writeBack ();
            else if (event.target == okButton) {
                writeBack ();
                close ();
            }
            else if (event.target == cancelButton)
                close ();
            else
                return super.handleEvent (event);
        }
        else
            return super.handleEvent (event);

        return true;
    }
}
