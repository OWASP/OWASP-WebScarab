/*
 * ManualEditFrameFactory.java
 *
 * Created on October 9, 2003, 8:31 AM
 */

package org.owasp.webscarab.ui.swing.proxy;

import org.owasp.webscarab.plugin.proxy.module.ConversationEditor;
import org.owasp.webscarab.plugin.proxy.module.ConversationEditorFactory;

/**
 *
 * @author  rdawes
 */
public class ManualEditFrameFactory implements ConversationEditorFactory {
    
    /** Creates a new instance of ManualEditFrameFactory */
    public ManualEditFrameFactory() {
    }
    
    public ConversationEditor getEditor() {
        return new ManualEditFrame();
    }
    
}
