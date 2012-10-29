package org.owasp.webscarab.plugin.identity;

import org.owasp.webscarab.model.ConversationModel;

public class ScriptableIdentity {

	private Identity identity;
	
	public ScriptableIdentity(Identity identity) {
		this.identity = identity;
	}
	
	public ConversationModel getConversationModel() {
		return identity.getFramework().getModel().getConversationModel();
	}
	
	public void removeTransitions() {
		identity.removeTransitions();
	}
}
