/*
 * FuzzFactory.java
 *
 * Created on 17 June 2005, 03:29
 */

package org.owasp.webscarab.plugin.fuzz;

import java.io.IOException;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;

import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;

/**
 *
 * @author  rogan
 */
public class FuzzFactory {
    
    /** Creates a new instance of FuzzFactory */
    public FuzzFactory() {
    }
    
    public String[] getSources() {
        return new String[] {"XSS Strings", "SQL Injection Strings"};
    }
    
    public FuzzSource getSource(String source) {
        if (source.equals("XSS Strings")) {
            return new ArraySource(source, new String[] {"<b>text</b>", "<script>alert(\"Gotcha\");</script>"});
        } else if (source.equals("SQL Injection Strings")) {
            return new ArraySource(source, new String[] {"a", "' --", "\" --"});
        } else if (source.toLowerCase().startsWith ("test")) {
            String count = source.substring(4).trim();
            try {
                return getTestSource(Integer.parseInt(count));
            } catch (Exception e) {}
        }
        return null;
    }
    
    public FuzzSource getTestSource(int count) {
        String[] items = new String[count];
        for (int i=0; i<count; i++) {
            items[i] = "Item " + i;
        }
        return new ArraySource("Test " + count, items);
    }
    
    private class FileSource implements FuzzSource {
        
        private String _description;
        private String[] _items;
        private int _index = 0;
        
        public FileSource(String description, File source) throws IOException {
            _description = description;
            BufferedReader br = new BufferedReader(new FileReader(source));
            String line;
            List items = new LinkedList();
            while ((line = br.readLine()) != null) {
                items.add(line);
            }
            br.close();
            _items = (String[]) items.toArray(new String[items.size()]);
        }
        
        public String getDescription() {
            return _description;
        }
        
        public void increment() {
            _index++;
        }
        
        public boolean hasNext() {
            return _index < _items.length-1;
        }
        
        public void reset() {
            _index = 0;
        }
        
        public int size() {
            return _items.length;
        }
        
        protected String[] getItems() {
            return _items;
        }
        
        public Object current() {
            return _items[_index];
        }
        
    }
    
    private class ArraySource implements FuzzSource {
        
        private String _description;
        private String[] _items;
        private int _index = 0;
        
        public ArraySource(String description, String[] items) {
            _description = description;
            _items = items;
        }
        
        public String getDescription() {
            return _description;
        }
        
        public int size() {
            return _items.length;
        }
        
        public void reset() {
            _index = 0;
        }
        
        public void increment() {
            _index++;
        }
        
        public boolean hasNext() {
            return _index < _items.length-1;
        }
        
        public Object current() {
            return _items[_index];
        }
        
    }
    
}
