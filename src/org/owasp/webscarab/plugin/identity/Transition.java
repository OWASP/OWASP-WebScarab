package org.owasp.webscarab.plugin.identity;

import java.util.Date;

import org.owasp.webscarab.model.ConversationID;

public class Transition {
	private ConversationID conversation;
	private Date date;
	private String tokenName, tokenValue, identity;

	public Transition(ConversationID conversation, Date date, String tokenName, String tokenValue, String identity) {
		this.conversation = conversation;
		this.date = date;
		this.tokenName = tokenName;
		this.tokenValue = tokenValue;
		this.identity = identity;
	}
	
	public ConversationID getConversation() {
		return conversation;
	}

	public Date getDate() {
		return date;
	}
	
	public String getTokenName() {
		return tokenName;
	}
	
	public String getTokenValue() {
		return tokenValue;
	}
	
	public String getIdentity() {
		return identity;
	}

}