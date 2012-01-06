/*
 * EditorFactory.java
 *
 * Created on 16 December 2004, 12:31
 */

package org.owasp.webscarab.ui.swing.editors;

import java.util.Map;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Logger;

import java.awt.Component;

/**
 *
 * @author  rogan
 */
public class EditorFactory {
    
    private static Map<String, List<String>> _editors = null;
    
    private static ByteArrayEditor[] NONE = new ByteArrayEditor[0];
    
    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.ui.swing.editors.EditorFactory");
    
    /** Creates a new instance of EditorFactory */
    private EditorFactory() {
    }
    
    static {
        _editors = new LinkedHashMap<String, List<String>>(); // this helps to maintain the order of the editors
        registerEditor("multipart/form-data; *.*", "org.owasp.webscarab.ui.swing.editors.MultiPartPanel");
        registerEditor("application/x-serialized-object", "org.owasp.webscarab.ui.swing.editors.SerializedObjectPanel");
        registerEditor("image/.*", "org.owasp.webscarab.ui.swing.editors.ImagePanel");
        registerEditor("application/x-www-form-urlencoded(;.*){0,1}", "org.owasp.webscarab.ui.swing.editors.UrlEncodedPanel");
        registerEditor("text/html.*","org.owasp.webscarab.ui.swing.editors.HTMLPanel");
        registerEditor("text/html.*","org.owasp.webscarab.ui.swing.editors.XMLPanel");
        registerEditor("text/xml.*","org.owasp.webscarab.ui.swing.editors.XMLPanel");
        registerEditor("text/.*","org.owasp.webscarab.ui.swing.editors.TextPanel");
        registerEditor("application/x-javascript(;.*){0,1}","org.owasp.webscarab.ui.swing.editors.TextPanel");
        registerEditor("application/x-www-form-urlencoded(;.*){0,1}","org.owasp.webscarab.ui.swing.editors.TextPanel");
        registerEditor("application/x-amf(;.*){0,1}","org.owasp.webscarab.ui.swing.editors.AMFPanel");
        registerEditor(".*", "org.owasp.webscarab.ui.swing.editors.HexPanel");
        // registerEditor(".*","org.owasp.webscarab.ui.swing.editors.CompressedTextPanel");
    }
    
    public static void registerEditor(String contentType, String editorClass) {
        List<String> list = _editors.get(contentType);
        if (list == null) {
            list = new ArrayList<String>();
            _editors.put(contentType, list);
        }
        if (list.indexOf(editorClass)<0) list.add(editorClass);
    }
    
    public static ByteArrayEditor[] getEditors(String contentType) {
        if (contentType == null) return new ByteArrayEditor[] { new HexPanel() };
        Iterator<String> it = _editors.keySet().iterator();
        List<ByteArrayEditor> editors = new ArrayList<ByteArrayEditor>();
        while (it.hasNext()) {
            String type = it.next();
            if (contentType.matches(type)) {
                List<String> list = _editors.get(type);
                Iterator<String> it2 = list.iterator();
                while (it2.hasNext()) {
                    String className = it2.next();
                    try {
                        Object ed = Class.forName(className).newInstance();
                        if (ed instanceof ByteArrayEditor && ed instanceof Component) {
                            editors.add((ByteArrayEditor) ed);
                        } else {
                            _logger.warning("Editor " + className + " must implement ByteArrayEditor and Component");
                        }
                    } catch (Exception e) {
                        _logger.warning("Exception trying to instantiate " + className + " : " + e);
                    }
                }
            }
        }
        return editors.toArray(NONE);
    }
    
}
