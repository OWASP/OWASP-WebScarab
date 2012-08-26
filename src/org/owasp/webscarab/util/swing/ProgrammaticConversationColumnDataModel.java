package org.owasp.webscarab.util.swing;

import org.apache.bsf.BSFException;
import org.apache.bsf.BSFManager;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

public class ProgrammaticConversationColumnDataModel extends ColumnDataModel<ConversationID> {

	private BSFManager manager = new BSFManager();
	
	private FrameworkModel model;
	
	private String name, language, expression;
	
	public ProgrammaticConversationColumnDataModel(FrameworkModel model, String name, String language, String expression) throws BSFException {
		super(name, Object.class);
		this.model = model;
		manager.declareBean("model", model, FrameworkModel.class);
		this.language = language;
		this.expression = expression;
	}
	
	@Override
	public Object getValue(ConversationID key) {
		try {
			manager.declareBean("id", key, ConversationID.class);
			Request request = model.getRequest(key);
			manager.declareBean("request", request, Request.class);
			Response response = model.getResponse(key);
			manager.declareBean("response", response, Response.class);
			Object result = manager.eval(language, name, 0, 0, expression);
			manager.undeclareBean("id");
			manager.undeclareBean("request");
			manager.undeclareBean("response");
			return result;
		} catch (BSFException bsfe) {
			return bsfe;
		}
	}
	
}
