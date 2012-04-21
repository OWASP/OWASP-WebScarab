package org.owasp.webscarab.ui.swing;

import java.awt.Component;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableCellRenderer;

public class EnabledBooleanTableCellRenderer extends JCheckBox implements
		TableCellRenderer {

	private static final Border noFocusBorder = new EmptyBorder(1, 1, 1, 1);

	public EnabledBooleanTableCellRenderer() {
		super();
		setHorizontalAlignment(JLabel.CENTER);
		setBorderPainted(true);
	}

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		if (value == null)
			return table.getDefaultRenderer(Object.class)
					.getTableCellRendererComponent(table, value, isSelected,
							hasFocus, row, column);

		setEnabled(table.isCellEditable(row, column));
		if (isSelected) {
			setForeground(table.getSelectionForeground());
			super.setBackground(table.getSelectionBackground());
		} else {
			setForeground(table.getForeground());
			setBackground(table.getBackground());
		}
		setSelected((value != null && ((Boolean) value).booleanValue()));
		if (hasFocus) {
			setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
		} else {
			setBorder(noFocusBorder);
		}
		return this;
	}
}
