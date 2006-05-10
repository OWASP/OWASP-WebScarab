/**
 * 
 */
package org.owasp.webscarab.util.swing;

/**
 * @author rdawes
 * 
 */

import javax.swing.text.*;

public class NoWrapEditorKit extends StyledEditorKit {

	private static final long serialVersionUID = 2867130121374027370L;

	public ViewFactory getViewFactory() {
		return new StyledViewFactory();
	}

	static class StyledViewFactory implements ViewFactory {
		public View create(Element elem) {
			String kind = elem.getName();

			if (kind != null) {
				if (kind.equals(AbstractDocument.ContentElementName)) {
					return new MyLabelView(elem);
				} else if (kind.equals(AbstractDocument.ParagraphElementName)) {
					return new ParagraphView(elem);
				} else if (kind.equals(AbstractDocument.SectionElementName)) {
					return new NoWrapBoxView(elem, View.Y_AXIS);
				} else if (kind.equals(StyleConstants.ComponentElementName)) {
					return new ComponentView(elem);
				} else if (kind.equals(StyleConstants.IconElementName)) {
					return new IconView(elem);
				}
			}

			return new LabelView(elem);
		}
	}

	static class NoWrapBoxView extends BoxView {
		public NoWrapBoxView(Element elem, int axis) {
			super(elem, axis);
		}

		public void layout(int width, int height) {
			super.layout(32768, height);
		}

		public float getMinimumSpan(int axis) {
			return super.getPreferredSpan(axis);
		}
	}

	static class MyLabelView extends LabelView {
		public MyLabelView(Element elem) {
			super(elem);
		}

		public float getPreferredSpan(int axis) {
			float span = 0;
			if (axis == View.X_AXIS) {
				int p0 = getStartOffset();
				int p1 = getEndOffset();
				checkPainter();
				TabExpander ex = getTabExpander();
				if (ex == null) {
					// paragraph implements TabExpander
					ex = (TabExpander) this.getParent().getParent();
				}
				span = getGlyphPainter().getSpan(this, p0, p1, ex, 0);
				return Math.max(span, 1);
			} else {
				span = super.getPreferredSpan(axis);
			}
			return span;
		}
	}

}
