package org.owasp.webscarab.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class RFC2822 {
	
	private static String datePattern = "EEE, dd MMM yyyy HH:mm:ss Z";

	public static Date parseDate(String dateString) throws ParseException {
		SimpleDateFormat format = new SimpleDateFormat(datePattern, Locale.ENGLISH);
		return format.parse(dateString);
	}
	
}
