package org.owasp.webscarab.plugin.identity;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

public class CookieTokenParser implements TokenParser {

	private String[] requestHeaders = new String[] { "Cookie", "Cookie2" },
			responseHeaders = new String[] { "Set-Cookie", "Set-Cookie2" };

	@Override
	public List<NamedValue> getTokens(Request request) {
		List<NamedValue> tokens = new LinkedList<NamedValue>();
		for (String headerName : requestHeaders) {
			String[] headers = request.getHeaders(headerName);
			if (headers == null)
				continue;
			for (String header : headers) {
				NamedValue[] cookies = NamedValue.splitNamedValues(header,
						";\\s*", "=");
				if (cookies != null)
					for (NamedValue cookie : cookies)
						tokens.add(cookie);
			}
		}
		return tokens.size() == 0 ? null : tokens;
	}

	@Override
	public List<NamedValue> getTokens(Response response) {
		Date date = null;
		
		// date is not strictly required if all we are doing is getting the
		// cookie value
		
		// String dateHeader = response.getHeader("Date");
		// if (dateHeader != null)
		// try {
		// date = RFC2822.parseDate(response.getHeader("Date"));
		// } catch (ParseException e) {
		// }

		List<NamedValue> tokens = new LinkedList<NamedValue>();
		for (String headerName : responseHeaders) {
			String[] headers = response.getHeaders(headerName);
			if (headers == null)
				continue;
			for (String header : headers) {
				Cookie cookie = new Cookie(date, header);
				tokens.add(new NamedValue(cookie.getName(), cookie.getValue()));
			}
		}
		return tokens.size() == 0 ? null : tokens;
	}

}
