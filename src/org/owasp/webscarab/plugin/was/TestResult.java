/*
 * TestResult.java
 *
 * Created on October 13, 2003, 9:55 PM
 */

package org.owasp.webscarab.plugin.was;

/**
 *
 * @author  rdawes
 */
public class TestResult {
    
    public static final int SUCCESS = 0;
    public static final int ERROR = 1;
    public static final int FAILURE = 2;
    
    private int _result;
    private String _message;
    
    /** Creates a new instance of TestResult */
    public TestResult(int result, String message) {
        _result = result;
        _message = message;
    }
    
    public TestResult(String result, String message) {
        if (result.equalsIgnoreCase("success")) {
            _result = SUCCESS;
        } else if (result.equalsIgnoreCase("error")) {
            _result = ERROR;
        } else if (result.equalsIgnoreCase("failure")) {
            _result = FAILURE;
        } else {
            _result = -1;
        }
        _message = message;
    }
    
    public boolean isSuccess() {
        return _result == SUCCESS;
    }
    
    public boolean isError() {
        return _result == ERROR;
    }
    
    public boolean isFailure() {
        return _result == FAILURE;
    }
    
    public String getMessage() {
        return _message;
    }
    
}
