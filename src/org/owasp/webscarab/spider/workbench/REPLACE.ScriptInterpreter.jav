/*
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University 
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software 
 * Foundation, version 2.
 *
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.spider.workbench;

public interface ScriptInterpreter {
    /**
     * Return name of language this interpreter handles.
     * @return Language name, such as "Javascript" or "TCL"
     */
    public abstract String getLanguage ();

    /**
     * Evaluate an expression in the script language.
     * @param expression Expression to evaluate
     * @exception ScriptException if execution encounters an error
     */
    public abstract Object eval (String expression) throws ScriptException;

    /**
     * Construct a procedure or function.
     * @param args Argument names
     * @param body Function body
     * @return Function object suitable for apply()
     * @exception ScriptException if execution encounters an error
     */
    public abstract Object lambda (String[] args, String body) throws ScriptException;

    /**
     * Call a procedure or function.
     * @param func Function object (previously returned by lambda()
     * @param args Arguments for the function
     * @exception ScriptException if execution encounters an error
     */
    public abstract Object apply (Object func, Object[] args) throws ScriptException;

    /**
     * Set a variable in the interpreter's global namespace
     * @param name Name of variable
     * @param object New value for variable
     */
    public abstract void set (String name, Object object);

    /**
     * Get a variable defined in the interpreter's global
     * namespace
     * @param name Name of variable to get
     * @return Value of variable, or null if not defined
     */
    public abstract Object get (String name);
}
