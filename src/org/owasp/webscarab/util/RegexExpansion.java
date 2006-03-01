/*
 * RegexExpansion.java
 *
 * Created on 28 February 2006, 04:15
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.util;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.PatternSyntaxException;

/**
 * This class creates a sequence of Strings that match a reduced Regular Expression 
 * syntax. This syntax excludes anything that might allow for variable length strings, 
 * or wildcards that would make the character range too large.
 *
 * Some examples of acceptable regular expression constructs:
 * ABCDEF = a sequence of 1 string "ABCDEF"
 * [AB] = a sequence of 2 : { "A", "B" }
 * [A-C] = a sequence of 3 : { "A", "B", "C" }
 * [AB]{2} = a sequence of 4 : { "AA", "AB", "BA", "BB" }
 * [AB]\{ = a sequence of 2: { "A{", "B{" }
 *
 * One specific limitation is that the size of the expansion sequence must fit into an int
 * An expansion that will not fit into an int will throw a PatternSyntaxException during construction
 * In practice, this should not really be a problem.
 *
 * @author rdawes
 */
public class RegexExpansion {
    
    private String regex;
    private int size = 0;
    private int index = 0;
    private char[][] charsets;
    
    /** Creates a new instance of RegexExpansion */
    public RegexExpansion(String regex) throws PatternSyntaxException {
        this.regex = regex;
        List charsets = new LinkedList();
        List chars = new LinkedList();
        
        boolean inClass = false;
        boolean quoted = false;
        String quantifier = null;
        char range = '\0';
        for (int index = 0; index < regex.length(); index++) {
            char ch = regex.charAt(index);
            if (!quoted && !inClass && (ch == '.' || ch == '*' || ch == '?')) {
                throw new PatternSyntaxException("No wildcards permitted", regex, index);
            }
            if (quantifier != null && ch != '}') {
                if (!Character.isDigit(ch)) 
                    throw new PatternSyntaxException("Illegal non-digit character in quantifier", regex, index);
                quantifier = quantifier + ch;
                continue;
            } else if (quoted) {
                chars.add(new Character(ch));
                quoted = false;
            } else
                switch (ch) {
                    case '[' : 
                        inClass = true; 
                        continue;
                    case ']' : 
                        inClass = false; 
                        break;
                    case '\\' : 
                        quoted = true; 
                        continue;
                    case '{' :
                        if (charsets.size()==0)
                            throw new PatternSyntaxException("Illegal quantifier at start of regex", regex, index);
                        quantifier = ""; 
                        continue;
                    case '}' : 
                        try {
                            int c = Integer.parseInt(quantifier);
                            if (c == 0)
                                throw new PatternSyntaxException("Cannot repeat 0 times", regex, index);
                            for (int i=1; i<c; i++)
                                charsets.add(charsets.get(charsets.size()-1));
                        } catch (NumberFormatException nfe) {
                            throw new PatternSyntaxException(nfe.getMessage(), regex, index);
                        }
                        quantifier = null; 
                        continue;
                    case '-' : 
                        if (inClass) {
                            range = ((Character)chars.get(chars.size()-1)).charValue();
                            continue;
                        }
                    default :
                        if (range != '\0') {
                            if (ch<=range) throw new PatternSyntaxException("Illegal range definition", regex, index);
                            for (char q=++range;q<=ch;q++) 
                                chars.add(new Character(q));
                            range = '\0';
                        } else
                            chars.add(new Character(ch));
                }
            if (!inClass) {
                charsets.add(chars);
                chars = new LinkedList();
            }
        }
        this.charsets = new char[charsets.size()][];
        for (int i=0; i<charsets.size(); i++) {
            chars = (List) charsets.get(i);
            char[] t = new char[chars.size()];
            for (int j=0; j<chars.size();j++) {
                t[j] = ((Character) chars.get(j)).charValue();
            }
            this.charsets[i] = t;
        }
        this.size = 1;
        for (int i=0; i<this.charsets.length; i++) {
            this.size = this.size * this.charsets[i].length;
            if (size == 0)
                throw new PatternSyntaxException("Pattern expansion overflow at position " + i, regex, 0);
        }
    }
    
    /**
     * Copy constructor
     * @param re the RegexExpansion to copy
     */
    protected RegexExpansion(RegexExpansion re) {
        this.regex = regex;
        this.charsets = re.charsets;
        this.size = re.size;
        this.index = 0;
    }
    
    /**
     * Returns the expression that is being expanded
     * @return the regular expression that is being expanded
     */
    public String getRegex() {
        return this.regex;
    }
    
    /**
     * returns the number of items in the expansion
     * @return the number of items in the expansion
     */
    public int size() {
        return this.size;
    }
    
    /**
     * sets the current position in the expansion sequence
     * @param index 
     */
    public void setIndex(int index) {
        if (index >= size)
            throw new ArrayIndexOutOfBoundsException("Index out of bounds: " + index + " >= " + size);
        this.index = index;
    }
    
    /**
     * 
     * @return 
     */
    public int getIndex() {
        return this.index;
    }
    
    /**
     * 
     * @return 
     */
    public boolean hasNext() {
        return getIndex() < size();
    }
    
    /**
     * 
     * @return 
     */
    public String next() {
        if (index >= size)
            throw new ArrayIndexOutOfBoundsException("Index out of bounds: " + index + " >= " + size);
        return get(index++);
    }
    
    /**
     * 
     * @param index 
     * @return 
     */
    public String get(int index) {
        if (index >= size)
            throw new ArrayIndexOutOfBoundsException("Index out of bounds: " + index + " >= " + size);
        StringBuffer buff = new StringBuffer(charsets.length);
        for (int i = charsets.length - 1; i >= 0; i--) {
            int mod = index % charsets[i].length;
            index = index / charsets[i].length;
            buff.insert(0,charsets[i][mod]);
        }
        return buff.toString();
    }

    public static void main(String[] args) {
        RegexExpansion re = new RegexExpansion("[0-9A-F]{8}");
        System.out.println("Size " + re.size());
    }
}
