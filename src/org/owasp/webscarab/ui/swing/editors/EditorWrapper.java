/*
 * EditorWrapper.java
 *
 * Created on May 17, 2004, 10:03 PM
 */

package org.owasp.webscarab.ui.swing.editors;

import java.util.logging.Logger;

import java.awt.Component;

/**
 *
 * @author  knoppix
 */
public class EditorWrapper {
    
    private String _className;
    private String[] _types;
    private ByteArrayEditor _editor = null;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of EditorWrapper */
    public EditorWrapper(String className, String[] contentTypes) {
        _className = className;
        _types = contentTypes;
    }
    
    private void loadEditor() {
        try {
            Object object = Class.forName(_className).newInstance();
            if (object instanceof ByteArrayEditor && object instanceof Component) {
                _editor = (ByteArrayEditor) object;
            } else {
                _logger.warning("class '" + _className + "' must implement Component and ByteArrayEditor");
            }
        } catch (Exception e) {
            _logger.severe("Failed to load editor '" + _className + "'");
        }
    }
    
    public Component getEditorComponent() {
        if (_editor == null) loadEditor();
        return (Component) _editor;
    }
    
    public boolean canEdit(String type) {
        for (int i=0; i<_types.length; i++) {
            if (type.matches(_types[i])) {
                return true;
            }
        }
        return false;
    }
    
}
