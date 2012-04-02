package org.owasp.webscarab.plugin.identity;

import java.util.List;

import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

public interface TokenParser {

	List<NamedValue> getTokens(Request request);
	
	List<NamedValue> getTokens(Response response);
	
}
