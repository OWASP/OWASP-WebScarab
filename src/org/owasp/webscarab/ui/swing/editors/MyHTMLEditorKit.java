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

/**
 *
 * @author  rdawes
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
		if (kind == HTML.Tag.FRAME || kind == HTML.Tag.FRAMESET || kind == HTML.Tag.IMG || kind == HTML.Tag.OBJECT || kind == HTML.Tag.APPLET) {
		    return new BlockView(elem, View.X_AXIS) {
			public float getPreferredSpan(int axis) {
			    return 0;
			}
			public float getMinimumSpan(int axis) {
			    return 0;
			}
			public float getMaximumSpan(int axis) {
			    return 0;
			}
			protected void loadChildren(ViewFactory f) {
			}
                        public Shape modelToView(int pos, Shape a,
                               Position.Bias b) throws BadLocationException {
                            return a;
                        }
			public int getNextVisualPositionFrom(int pos,
				     Position.Bias b, Shape a, 
				     int direction, Position.Bias[] biasRet) {
			    return getElement().getEndOffset();
			}
		    };
                }
            }
            return super.create(elem);
        }
    }
    
}
