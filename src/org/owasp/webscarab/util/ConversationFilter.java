/*
 * ConversationFilter.java
 *
 * Created on May 13, 2004, 10:35 AM
 */

package org.owasp.webscarab.util;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.SiteModel;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author  knoppix
 */
public class ConversationFilter extends Filter {
    
    private SiteModel _siteModel;
    private ConversationCriteria[] _criteria;
    
    private Conversation _conversation = null;
    private Request _request = null;
    private Response _response = null;
    
    /** Creates a new instance of ConversationFilter */
    public ConversationFilter(SiteModel siteModel, ConversationCriteria[] criteria) {
        _siteModel = siteModel;
        if (_siteModel == null) {
            throw new NullPointerException("SiteModel cannot be null!");
        }
        setCriteria(criteria);
    }
    
    public void setCriteria(ConversationCriteria[] criteria) {
        _criteria = criteria;
        if (_criteria == null) {
            _criteria = new ConversationCriteria[0];
        }
        fireFilterChanged();
    }
    
    public boolean filtered(Object object) {
        if (object instanceof Conversation) {
            _conversation = (Conversation) object;
            _request = null;
            _response = null;
            boolean matches = false;
            for (int i=0; i<_criteria.length; i++) {
                String logic = _criteria[i].getLogic();
                // do some short circuit processing
                if (!matches && logic.equalsIgnoreCase("AND")) {
                    continue;
                } else if (matches && logic.equalsIgnoreCase("OR")) {
                    return !matches;
                }
                String locationValue = getLocationValue(_criteria[i].getLocation());
                String operation = _criteria[i].getOperation();
                String match = _criteria[i].getMatch();
                boolean result = evaluate(locationValue, operation, match);
                if (logic.equalsIgnoreCase("AND")) {
                    matches = matches && result;
                } else {
                    matches = matches || result;
                }
            }
            return !matches;
        }
        return true; // we filter non-conversations
    }

    private String getLocationValue(String location) {
        // we fetch the request and response lazily, if we have enough info in 
        // the Conversation to get the data
        if (location.equalsIgnoreCase("Request Method")) {
            return _conversation.getProperty("METHOD");
        } else if (location.equalsIgnoreCase("Request URL")) {
            return _conversation.getProperty("URL");
        } else if (location.equalsIgnoreCase("Request Headers")) {
            if (_request == null) {
                _request = _siteModel.getRequest(_conversation.getProperty("ID"));
            }
            return headersToString(_request.getHeaders());
        } else if (location.equalsIgnoreCase("Request Body")) {
            if (_request == null) {
                _request = _siteModel.getRequest(_conversation.getProperty("ID"));
            }
            return new String(_request.getContent());
        } else if (location.equalsIgnoreCase("Response status")) {
            return _conversation.getProperty("STATUS");
        } else if (location.equalsIgnoreCase("Response Headers")) {
            if (_response == null) {
                _response = _siteModel.getResponse(_conversation.getProperty("ID"));
            }
            return headersToString(_response.getHeaders());
        } else if (location.equalsIgnoreCase("Response Body")) {
            if (_response == null) {
                _response = _siteModel.getResponse(_conversation.getProperty("ID"));
            }
            return new String(_response.getContent());
        }
        System.err.println("Unknown location: '" + location + "'");
        return "";
    }
    
    private String headersToString(String[][] headers) {
        StringBuffer buff = new StringBuffer(128);
        for (int j=0; j<headers.length; j++) {
            buff.append(headers[j][0]).append(": ");
            buff.append(headers[j][1]).append("\n");
        }
        return buff.toString();
    }
    
    private boolean evaluate(String left, String operation, String right) {
        if (operation.equalsIgnoreCase("equals")) {
            return left.equals(right);
        } else if (operation.equalsIgnoreCase("not equals")) {
            return ! left.equals(right);
        } else if (operation.equalsIgnoreCase("contains")) {
            return left.indexOf(right) > -1;
        } else if (operation.equalsIgnoreCase("not contains")) {
            return ! (left.indexOf(right) > -1);
        } else if (operation.equalsIgnoreCase("matches")) {
            try {
                Pattern pattern = Pattern.compile(right, Pattern.MULTILINE | Pattern.DOTALL);
                Matcher matcher = pattern.matcher(left);
                return matcher.matches();
            } catch (PatternSyntaxException pse) {
                System.err.println("Exception: " + pse);
            }
        } else if (operation.equalsIgnoreCase("not matches")) {
            try {
                Pattern pattern = Pattern.compile(right, Pattern.MULTILINE | Pattern.DOTALL);
                Matcher matcher = pattern.matcher(left);
                return ! matcher.matches();
            } catch (PatternSyntaxException pse) {
                System.err.println("Exception: " + pse);
            }
        }
        System.err.println("Unknown operation '" + operation + "'");
        return false;
    }
    
}
