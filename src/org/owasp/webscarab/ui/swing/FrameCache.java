/*
 * FrameCache.java
 *
 * Created on May 13, 2004, 11:57 AM
 */

package org.owasp.webscarab.ui.swing;

import java.util.Map;
import java.util.HashMap;
import javax.swing.JFrame;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 *
 * @author  knoppix
 */
public class FrameCache {

    private static Map _cache = new HashMap();
    private static WindowAdapter _listener = new WindowAdapter() {
        public void windowClosing(WindowEvent evt) {
            JFrame frame = (JFrame) evt.getSource();
            removeFrame(frame.getTitle());
        }
    };
    
    /** Creates a new instance of FrameCache */
    private FrameCache() {
    }
    
    public static JFrame getFrame(String title) {
        synchronized(_cache) {
            return (JFrame) _cache.get(title);
        }
    }
    
    public static JFrame addFrame(String title, JFrame frame) {
        synchronized(_cache) {
            frame.addWindowListener(_listener);
            return (JFrame) _cache.put(title, frame);
        }
    }
    
    public static JFrame removeFrame(String title) {
        synchronized(_cache) {
            JFrame frame = (JFrame) _cache.remove(title);
            frame.removeWindowListener(_listener);
            return frame;
        }
    }
    
}
