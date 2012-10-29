package org.owasp.webscarab.plugin.identity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.FrameworkListener;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.util.NullComparator;

public class IdentityModel extends AbstractPluginModel {

	private FrameworkModel model;

	private Map<String, Map<String, SortedMap<ConversationID, Transition>>> transitions = new HashMap<String, Map<String, SortedMap<ConversationID, Transition>>>();

	private Map<ConversationID, List<String>> cache = new HashMap<ConversationID, List<String>>();

	private SortedSet<String> identities = new TreeSet<String>(new NullComparator());

	private Map<String, Map<String, List<ConversationID>>> conversations;
	
	public IdentityModel(FrameworkModel model) {
		this.model = model;
	}

	public void setStore(IdentityStore store) {
		
	}
	
	public void removeTransitions() {
		transitions.clear();
		cache.clear();
		identities.clear();
		conversations.clear();
	}
	
	public void addTransition(Transition transition) {
		Map<String, SortedMap<ConversationID, Transition>> values = transitions
				.get(transition.getTokenName());
		if (values == null) {
			values = new HashMap<String, SortedMap<ConversationID, Transition>>();
			transitions.put(transition.getTokenName(), values);
		}
		SortedMap<ConversationID, Transition> events = values.get(transition.getTokenValue());
		if (events == null) {
			events = new TreeMap<ConversationID, Transition>();
			values.put(transition.getTokenValue(), events);
		}
		events.put(transition.getConversation(), transition);
		identities.add(transition.getIdentity());
	}
	
	public SortedMap<ConversationID, Transition> getTransitions(String tokenName, String tokenValue) {
		Map<String, SortedMap<ConversationID, Transition>> values = transitions
				.get(tokenName);
		if (values == null)
			return null;
		SortedMap<ConversationID, Transition> events = values.get(tokenValue);
		if (events == null)
			return null;
		return new TreeMap<ConversationID, Transition>(events);
	}
	
	public Transition getIdentity(ConversationID id, String tokenName, String tokenValue) {
		Map<String, SortedMap<ConversationID, Transition>> values = transitions
				.get(tokenName);
		if (values == null)
			return null;
		SortedMap<ConversationID, Transition> events = values.get(tokenValue);
		if (events == null)
			return null;
		Iterator<Entry<ConversationID, Transition>> it = events.entrySet().iterator();
		Transition transition = null;
		while (it.hasNext()) {
			Entry<ConversationID, Transition> e = it.next();
			ConversationID cid = e.getKey();
			if (cid.compareTo(id) <= 0) {
				transition = e.getValue();
			} else {
				if (transition == null)
					return null;
				return transition;
			}
		}
		return null;
	}
	
	public Map<String, List<ConversationID>> getConversationsWithToken(String name) {
		return conversations.get(name);
	}
	
	public List<ConversationID> getConversationsWithTokenValue(String name, String value) {
		Map<String, List<ConversationID>> tokenMap = getConversationsWithToken(name);
		if (tokenMap == null)
			return null;
		return tokenMap.get(value);
	}
	
	public List<String> getTokens() {
		return new ArrayList<String>(conversations.keySet());
	}
	
	public List<String> getTokenValues(String name) {
		Map<String, List<ConversationID>> tokenMap = getConversationsWithToken(name);
		if (tokenMap == null)
			return null;
		return new ArrayList<String>(tokenMap.keySet());
	}
	
	public List<String> getIdentities() {
		return new ArrayList<String>(identities);
	}
}
