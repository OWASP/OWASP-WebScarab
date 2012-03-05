package org.owasp.webscarab.plugin.identity.swing;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.plugin.identity.Identity;

class SelectTokenDialog extends JDialog {
	
	private Identity identity;
	
	private JTable table;
	private JComboBox comboBox;
	private JButton btnOk;
	private TokenTableModel ttm;
	private IdentityComboModel icm;
	
	private ConversationID conversation;
	
	private boolean cancelled = true;
	
	public SelectTokenDialog(final Identity identity, Window window) {
		super(window);
		this.identity = identity;
	
		setAlwaysOnTop(true);
		setTitle("Select Token");
		setModal(true);
		setMinimumSize(new Dimension(400, 300));
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0,
				Double.MIN_VALUE };
		getContentPane().setLayout(gridBagLayout);

		JScrollPane scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.weighty = 1.0;
		gbc_scrollPane.weightx = 1.0;
		gbc_scrollPane.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 0;
		getContentPane().add(scrollPane, gbc_scrollPane);

		ttm = new TokenTableModel();
		table = new JTable(ttm);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(table);
		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				int row = table.getSelectedRow();
				comboBox.setEnabled(row >= 0);
				btnOk.setEnabled(row >= 0);
				if (row >= 0) {
					NamedValue token = ttm.getToken(row);
					String id = identity.getIdentity(getConversation(), token);
					comboBox.setSelectedItem(id);
				} else {
					comboBox.setSelectedItem(null);
				}
			}
		});

		JLabel lblIdentity = new JLabel("Identity");
		GridBagConstraints gbc_lblIdentity = new GridBagConstraints();
		gbc_lblIdentity.insets = new Insets(0, 0, 5, 5);
		gbc_lblIdentity.anchor = GridBagConstraints.EAST;
		gbc_lblIdentity.gridx = 0;
		gbc_lblIdentity.gridy = 1;
		getContentPane().add(lblIdentity, gbc_lblIdentity);

		icm = new IdentityComboModel();
		comboBox = new JComboBox(icm);
		comboBox.setToolTipText("Enter or select the identity");
		comboBox.setEnabled(false);
		comboBox.setEditable(true);
		GridBagConstraints gbc_comboBox = new GridBagConstraints();
		gbc_comboBox.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox.gridx = 1;
		gbc_comboBox.gridy = 1;
		getContentPane().add(comboBox, gbc_comboBox);

		JPanel panel = new JPanel();
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.weightx = 1.0;
		gbc_panel.anchor = GridBagConstraints.EAST;
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.gridx = 1;
		gbc_panel.gridy = 2;
		getContentPane().add(panel, gbc_panel);
		panel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		JButton btnCancel = new JButton("Cancel");
		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				setVisible(false);
			}
		});
		panel.add(btnCancel);

		btnOk = new JButton("Ok");
		btnOk.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				cancelled = false;
				setVisible(false);
			}
		});
		btnOk.setEnabled(false);
		panel.add(btnOk);
	}

	@Override
	public void setVisible(boolean b) {
		super.setVisible(b);
		if (b)
			cancelled = true;
	}

	public boolean isCancelled() {
		return cancelled;
	}
	
	public void setConversation(ConversationID id) {
		this.conversation = id;
	}
	
	public ConversationID getConversation() {
		return conversation;
	}
	
	public void setIdentities(List<String> identities) {
		icm.setIdentities(identities);
	}

	public String getSelectedIdentity() {
		return (String) icm.getSelectedItem();
	}
	
	public void setTokens(List<NamedValue> reqTokens,
			List<NamedValue> respTokens) {
		ttm.setTokens(reqTokens, respTokens);
	}

	public NamedValue getSelectedToken() {
		int row = table.getSelectedRow();
		return row < 0 ? null : ttm.getToken(row);
	}
	
	private static class TokenTableModel extends AbstractTableModel {

		private String[] names = new String[] { "Source", "Name", "Value" };
		
		private List<NamedValue> reqTokens, respTokens;
		private int reqCount = 0, respCount = 0;

		public void setTokens(List<NamedValue> reqTokens,
				List<NamedValue> respTokens) {
			this.reqTokens = reqTokens;
			reqCount = reqTokens == null ? 0 : reqTokens.size();
			this.respTokens = respTokens;
			respCount = respTokens == null ? 0 : respTokens.size();
			fireTableDataChanged();
		}

		public NamedValue getToken(int row) {
			if (row < reqCount)
				return reqTokens.get(row);
			else if (row < getRowCount())
				return respTokens.get(row - reqCount);
			return null;
		}
		
		@Override
		public String getColumnName(int column) {
			return names[column];
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}

		@Override
		public int getRowCount() {
			return reqCount + respCount;
		}

		@Override
		public int getColumnCount() {
			return 3;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			if (columnIndex == 0) {
				if (rowIndex < reqCount)
					return "Request";
				return "Response";
			}
			NamedValue token = getToken(rowIndex);
			if (token == null)
				return null;
			if (columnIndex == 1)
				return token.getName();
			return token.getValue();
		}

	}
	
	private static class IdentityComboModel extends AbstractListModel implements ComboBoxModel {

		private List<String> identities = new ArrayList<String>();
		private SortedSet<String> sorter = new TreeSet<String>();
		
		private String selected = null;
		
		public void setIdentities(List<String> identities) {
			sorter.clear();
			sorter.addAll(identities);
			this.identities.clear();
			this.identities.addAll(sorter);
			fireContentsChanged(this, -1, -1);
		}
		
		@Override
		public int getSize() {
			return identities.size();
		}

		@Override
		public Object getElementAt(int index) {
			return identities.get(index);
		}

		@Override
		public void setSelectedItem(Object anItem) {
			if (anItem instanceof String) {
				String item = (String) anItem;
				if (!identities.contains(item)) {
					sorter.add(item);
					identities.clear();
					identities.addAll(sorter);
				}
				selected = item;
			} else {
				selected = null;
			}
			fireContentsChanged(this, -1, -1);
		}

		@Override
		public Object getSelectedItem() {
			return selected;
		}
		
	}
}