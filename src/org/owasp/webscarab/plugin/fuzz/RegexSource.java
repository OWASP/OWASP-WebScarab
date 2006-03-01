/*
 * RegexSource.java
 *
 * Created on 28 February 2006, 06:16
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.fuzz;

import java.util.regex.PatternSyntaxException;
import org.owasp.webscarab.util.RegexExpansion;

/**
 *
 * @author rdawes
 */
public class RegexSource extends RegexExpansion implements FuzzSource {
    
    private String description;
    
    /** Creates a new instance of RegexSource */
    public RegexSource(String description, String regex) throws PatternSyntaxException {
        super(regex);
        this.description = description;
    }
    
    protected RegexSource(RegexSource rs) {
        super(rs);
        this.description = rs.description;
    }
    
    public Object current() {
        return super.get(super.getIndex());
    }

    public String getDescription() {
        return this.description;
    }

    public void increment() {
        super.next();
    }

    public FuzzSource newInstance() {
        return new RegexSource(this);
    }

    public void reset() {
        super.setIndex(0);
    }
    
}
