package org.owasp.webscarab.plugin.identity.swing;

import java.awt.Component;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.identity.Identity;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;

public class IdentityPanel extends javax.swing.JPanel implements SwingPluginUI {

	private Identity identity;
	private ColumnDataModel<ConversationID>[] conversationColumns;
	private Action[] conversationActions;
	private SelectTokenDialog std;

	public IdentityPanel(Identity identity) {
		this.identity = identity;
		add(new JLabel("Identity"));
	}

	@Override
	public String getPluginName() {
		return identity.getPluginName();
	}

	@Override
	public JPanel getPanel() {
		return this;
	}

	@Override
	public Action[] getUrlActions() {
		return null;
	}

	@Override
	public ColumnDataModel<HttpUrl>[] getUrlColumns() {
		return null;
	}

	@Override
	public Action[] getConversationActions() {
		if (conversationActions == null) {
			conversationActions = new Action[] { new AddIdentityAction() };
		}
		return conversationActions;
	}

	@Override
	public ColumnDataModel<ConversationID>[] getConversationColumns() {
		if (conversationColumns == null) {
			conversationColumns = new ColumnDataModel[] {

			new ColumnDataModel<ConversationID>("Identity", String.class) {
				public Object getValue(ConversationID key) {
					if (identity == null)
						return null;
					return identity
							.getFramework()
							.getModel()
							.getConversationModel()
							.getConversationProperty(key,
									"IDENTITY");
				}

			} };
		}
		return conversationColumns;
	}

	private class AddIdentityAction extends AbstractAction {

		private SelectTokenDialog std;

		/** Creates a new instance of ShowConversationAction */
		public AddIdentityAction() {
			putValue(NAME, "Add identity");
			putValue(SHORT_DESCRIPTION,
					"Associates an identity with this conversation");
			putValue("CONVERSATION", null);
		}

		public void actionPerformed(ActionEvent e) {
			Object o = getValue("CONVERSATION");
			if (o == null || !(o instanceof ConversationID))
				return;
			ConversationID conversation = (ConversationID) o;
			FrameworkModel fm = identity.getFramework().getModel();
			Request request = fm.getRequest(conversation);
			Response response = fm.getResponse(conversation);
			List<NamedValue> reqTokens = identity.getRequestTokens(request);
			List<NamedValue> respTokens = identity.getResponseTokens(response);
			Object c = getValue("COMPONENT");
			Component component = null;
			if (c instanceof Component)
				component = (Component) c;

			if (std == null) {
				if (component == null)
					component = IdentityPanel.this;
				Window window = SwingUtilities.getWindowAncestor(component);
				std = new SelectTokenDialog(identity, window);
			}
			std.setConversation(conversation);
			std.setTokens(reqTokens, respTokens);
			std.setIdentities(identity.getIdentities());
			std.setLocationRelativeTo(null);
			std.setVisible(true);
			boolean ok = !std.isCancelled();
			if (ok) {
				NamedValue token = std.getSelectedToken();
				String id = std.getSelectedIdentity();
				identity.addTransition(conversation, token.getName(),
						token.getValue(), id);
			}
		}

		public void putValue(String key, Object value) {
			super.putValue(key, value);
			if (key != null && key.equals("CONVERSATION")) {
				if (value != null && value instanceof ConversationID) {
					setEnabled(true);
				} else {
					setEnabled(false);
				}
			}
		}

	}

}
