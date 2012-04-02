package org.owasp.webscarab.plugin.identity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SortedMap;

import javax.swing.SwingUtilities;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.identity.swing.IdentityPanel;
import org.owasp.webscarab.plugin.proxy.Proxy;
import org.owasp.webscarab.plugin.proxy.swing.ProxyPanel;
import org.owasp.webscarab.ui.swing.UIFramework;
import org.owasp.webscarab.util.RFC2822;

public class Identity implements Plugin {

	private Framework framework;
	private IdentityModel model;
	private List<TokenParser> tokenParsers = new LinkedList<TokenParser>();

	public Identity(Framework framework) {
		this.framework = framework;
		model = new IdentityModel(framework.getModel());
		tokenParsers.add(new CookieTokenParser());
	}

	public Framework getFramework() {
		return framework;
	}

	public void addTransition(ConversationID conversation, String tokenName,
			String tokenValue, String identity) {
		Date date = getConversationDate(conversation);
		Transition transition = new Transition(conversation, date, tokenName,
				tokenValue, identity);
		model.addTransition(transition);
		SortedMap<ConversationID, Transition> transitions = model.getTransitions(tokenName, tokenValue);
		ConversationID next = null;
		Iterator<ConversationID> it = transitions.keySet().iterator();
		while (it.hasNext()) {
			if (it.next().equals(conversation)) {
				if (it.hasNext())
					next = it.next();
				break;
			}
		}
		ConversationModel cm = framework.getModel().getConversationModel();
		int c = cm.getConversationCount();
		if (next == null)
			next = cm.getConversationAt(c - 1);
		for (int i = 0; i < c; i++) {
			ConversationID id = cm.getConversationAt(i);
			if (id.compareTo(conversation) >= 0) { 
				// FIXME: When removing the identity, this should only take effect from the NEXT request.
				List<NamedValue> tokens = getRequestTokens(cm.getRequest(id));
				tokens.addAll(getResponseTokens(cm.getResponse(id)));
				for (NamedValue token : tokens) {
					if (token.getName().equals(tokenName) && token.getValue().equals(tokenValue)) {
						cm.setConversationProperty(id, "IDENTITY", identity);
						break;
					}
				}
			}
				
		}
	}

	public List<String> getIdentities() {
		return model.getIdentities();
	}

	public String getIdentity(ConversationID conversation, NamedValue token) {
		Transition transition = model.getIdentity(conversation, token.getName(),
				token.getValue());
		if (transition == null)
			return null;
		return transition.getIdentity();
	}

	public List<String> getIdentities(ConversationID conversation) {
		List<NamedValue> tokens = getRequestTokens(framework.getModel()
				.getRequest(conversation));
		List<String> identities = new LinkedList<String>();
		if (tokens == null)
			return null;
		for (NamedValue token : tokens) {
			Transition transition = model.getIdentity(conversation, token.getName(),
					token.getValue());
			if (transition == null)
				continue;
			identities.add(transition.getIdentity());
		}
		return identities.size() == 0 ? null : identities;
	}

	private Date getConversationDate(ConversationID id) {
		Response response = framework.getModel().getResponse(id);
		Date date = null;
		String serverTime = response.getHeader("Date");
		if (serverTime != null) {
			try {
				date = RFC2822.parseDate(serverTime);
			} catch (ParseException e) {
			}
		}
		if (date == null)
			date = framework.getModel().getConversationDate(id);
		return date;
	}

	public List<NamedValue> getRequestTokens(Request request) {
		List<NamedValue> tokens = new LinkedList<NamedValue>();
		for (TokenParser parser : tokenParsers) {
			List<NamedValue> list = parser.getTokens(request);
			if (list != null)
				tokens.addAll(list);
		}
		return tokens;
	}

	public List<NamedValue> getResponseTokens(Response response) {
		List<NamedValue> tokens = new LinkedList<NamedValue>();
		for (TokenParser parser : tokenParsers) {
			List<NamedValue> list = parser.getTokens(response);
			if (list != null)
				tokens.addAll(list);
		}
		return tokens;
	}

	@Override
	public String getPluginName() {
		return "Identity";
	}

	@Override
	public void setSession(String type, Object store, String session)
			throws StoreException {
		// TODO Auto-generated method stub

	}

	@Override
	public void run() {
		model.setRunning(true);
	}

	@Override
	public boolean isRunning() {
		return model.isRunning();
	}

	@Override
	public boolean isBusy() {
		return model.isBusy();
	}

	@Override
	public String getStatus() {
		return model.getStatus();
	}

	@Override
	public boolean stop() {
		model.setRunning(false);
		return !model.isRunning();
	}

	@Override
	public boolean isModified() {
		return model.isModified();
	}

	@Override
	public void flush() throws StoreException {
		// TODO Auto-generated method stub

	}

	@Override
	public void analyse(ConversationID id, Request request, Response response,
			String origin) {
		// TODO Auto-generated method stub

	}

	@Override
	public Hook[] getScriptingHooks() {
		return null;
	}

	@Override
	public Object getScriptableObject() {
		return null;
	}

	private static Identity identity;

	public static void main(String[] args) throws Exception {
		final Framework framework = new Framework();

		final UIFramework uif = new UIFramework(framework);

		loadAllPlugins(framework, uif);
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					uif.setVisible(true);
					uif.toFront();
					uif.requestFocus();
				}
			});
		} catch (Exception e) {
			System.err.println("Error loading GUI: " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
		new Thread() {
			public void run() {
				try {
					BufferedReader br = new BufferedReader(
							new InputStreamReader(System.in));
					System.out.println("Press Enter to add conversations");
					br.read();
					addConversations1(framework);
					System.out.println("Press Enter to add an identity");
					br.read();
					System.out.println("Adding identity to 2");
					addIdentity(framework);
					System.out.println("Press Enter to continue");
					br.read();
					System.out.println("Remove identity from 4");
					removeIdentity(framework);
					System.out.println("Press Enter to continue");
					br.read();
					addConversation3(framework);
					System.out.println("Press Enter to exit");
					br.read();
					System.exit(0);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
		uif.run();
		System.exit(0);
	}

	public static void loadAllPlugins(Framework framework, UIFramework uif) {
		Proxy proxy = new Proxy(framework);
		framework.addPlugin(proxy);
		ProxyPanel proxyPanel = new ProxyPanel(proxy);
		uif.addPlugin(proxyPanel);

		identity = new Identity(framework);
		framework.addPlugin(identity);
		IdentityPanel identityPanel = new IdentityPanel(identity);
		uif.addPlugin(identityPanel);
	}

	private static void addConversations1(Framework f) throws Exception {
		Request req = new Request();
		req.setMethod("GET");
		req.setURL(new HttpUrl("http://localhost/"));
		req.setVersion("HTTP/1.0");

		Response resp = new Response();
		resp.setVersion("HTTP/1.0");
		resp.setStatus("302");
		resp.setMessage("Moved");
		resp.setHeader("Location", "/auth?userid=joe");

		f.addConversation(new ConversationID(1), req, resp, "Identity");

		req = new Request();
		req.setMethod("GET");
		req.setURL(new HttpUrl("http://localhost/auth?userid=joe"));
		req.setVersion("HTTP/1.0");

		resp = new Response();
		resp.setVersion("HTTP/1.0");
		resp.setStatus("200");
		resp.setMessage("Ok");
		resp.setHeader("Set-Cookie", "session=abc");

		f.addConversation(new ConversationID(2), req, resp, "Identity");

		req = new Request();
		req.setMethod("GET");
		req.setURL(new HttpUrl("http://localhost/index"));
		req.setVersion("HTTP/1.0");
		req.setHeader("Cookie", "session=abc");

		resp = new Response();
		resp.setVersion("HTTP/1.0");
		resp.setStatus("200");
		resp.setMessage("Ok");

		f.addConversation(new ConversationID(3), req, resp, "Identity");

		req = new Request();
		req.setMethod("GET");
		req.setURL(new HttpUrl("http://localhost/logout"));
		req.setVersion("HTTP/1.0");
		req.setHeader("Cookie", "session=abc");

		resp = new Response();
		resp.setVersion("HTTP/1.0");
		resp.setStatus("200");
		resp.setMessage("Ok");

		f.addConversation(new ConversationID(4), req, resp, "Identity");

		req = new Request();
		req.setMethod("GET");
		req.setURL(new HttpUrl("http://localhost/index"));
		req.setVersion("HTTP/1.0");
		req.setHeader("Cookie", "session=abc");

		resp = new Response();
		resp.setVersion("HTTP/1.0");
		resp.setStatus("200");
		resp.setMessage("Ok");

		f.addConversation(new ConversationID(5), req, resp, "Identity");
}

	private static void addIdentity(Framework f) throws Exception {
		identity.addTransition(new ConversationID(2), "session", "abc", "joe");
		
	}

	private static void removeIdentity(Framework f) throws Exception {
		identity.addTransition(new ConversationID(4), "session", "abc", null);
		
	}

	private static void addConversation3(Framework f) throws Exception {

	}
}
