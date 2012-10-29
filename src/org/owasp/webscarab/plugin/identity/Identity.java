package org.owasp.webscarab.plugin.identity;

import java.io.File;
import java.text.ParseException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SortedMap;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
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

	public void removeTransitions() {
		model.removeTransitions();
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
    public void setSession(String type, Object store, String session) throws StoreException {
        if (type.equals("FileSystem") && (store instanceof File)) {
            model.setStore(new FileSystemStore((File) store, session));
        } else {
            throw new StoreException("Store type '" + type + "' is not supported in " + getClass().getName());
        }
    }

	@Override
	public void run() {
		model.setRunning(true);
		try {
			Thread.sleep(2000);
		} catch (InterruptedException ie) {}
		FrameworkModel fm = framework.getModel();
		ConversationModel cm = fm.getConversationModel();
		int c = cm.getConversationCount();
		for (int i=0; i < c; i++) {
			ConversationID cid = cm.getConversationAt(i);
			Request req = cm.getRequest(cid);
			HttpUrl url = req.getURL();
			List<NamedValue> tokens = getRequestTokens(req);
			if (url.toString().endsWith("logout.php")) {
				String sessid = tokens.get(0).getValue();
				addTransition(cid, "PHPSESSID", sessid, null);
			} else if (req.getMethod().equals("POST") && url.toString().endsWith("login.php")) {
				String sessid = null;
				if (tokens.size() > 0)
					sessid = tokens.get(0).getValue();
				Response response = cm.getResponse(cid);
				if (response.getStatus().equals("302")) {
					String who = null;
					tokens = getResponseTokens(response);
					if (tokens.size() > 0)
						sessid = tokens.get(0).getValue();
					String content = new String(req.getContent());
					NamedValue[] params = NamedValue.splitNamedValues(content, "&", "=");
					for (int j = 0; j<params.length; j++)
						if (params[j].getName().equals("user"))
							who = params[j].getValue();
					addTransition(cid, "PHPSESSID", sessid, who);
				}
			}
			
		}
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
}
