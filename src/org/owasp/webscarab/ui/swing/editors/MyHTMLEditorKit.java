/*
 * MyHTMLEditorKit.java
 *
 * Created on November 8, 2003, 12:37 PM
 */

package org.owasp.webscarab.ui.swing.editors;

import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.ViewFactory;
import javax.swing.text.Element;
import javax.swing.text.View;
import javax.swing.text.StyleConstants;
import javax.swing.text.html.HTML;
import javax.swing.text.html.BlockView;
import javax.swing.text.Position;
import javax.swing.text.BadLocationException;

import java.awt.Shape;
import java.awt.Rectangle;
import java.awt.Graphics;

/** We need to override the Default HTMLEditorKit to stop it from trying to follow
 * embedded links, such as framesets. This is because we don't know the
 * base URL of the HTML content we are rendering, and besides, we probably don't
 * want to go fetching embedded frames, which could possibly affect things on the
 * server. The ideal would probably be to get the most recent conversation for the
 * required URL from our local cache, but that becomes very intricate, and this is
 * probably good enough for now.
 * @author rdawes
 */
public class MyHTMLEditorKit extends javax.swing.text.html.HTMLEditorKit {
    private static final ViewFactory defaultFactory = new MyHTMLFactory();
    
    public ViewFactory getViewFactory() {
	return defaultFactory;
    }
    
    private static class MyHTMLFactory extends HTMLEditorKit.HTMLFactory {
        public View create(Element elem) {
            Object o = elem.getAttributes().getAttribute(StyleConstants.NameAttribute);
            if (o instanceof HTML.Tag) {
                HTML.Tag kind = (HTML.Tag) o;
                if (kind == HTML.Tag.FRAME || 
                    kind == HTML.Tag.FRAMESET || 
                    kind == HTML.Tag.OBJECT || 
                    kind == HTML.Tag.APPLET) {
                    return new NoView(elem);
                }
            }
            return super.create(elem);
        }
    }
    
    private static class NoView extends View {
        public NoView(Element elem) {
            super(elem);
            setSize(0.0f, 0.0f);
        }

        public int viewToModel(float fx, float fy, Shape a, Position.Bias[] bias) {
            return 0;
        }
        
        public Shape modelToView(int pos, Shape a, Position.Bias b) throws BadLocationException {
            return new Rectangle(0, 0);
        }

        public float getPreferredSpan(int axis) {
            return 0.0f;
        }

        public void paint(Graphics g, Shape allocation) {
        }
    }

}
