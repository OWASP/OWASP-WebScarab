/*
 * FuzzFactory.java
 *
 * Created on 17 June 2005, 03:29
 */

package org.owasp.webscarab.plugin.fuzz;

import java.io.IOException;
import java.io.File;
import java.io.Reader;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import java.beans.PropertyChangeSupport;
import java.beans.PropertyChangeListener;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author  rogan
 */
public class FuzzFactory {
    
    public static final String SOURCES = "Sources";
    
    private Map _sources = new TreeMap();
    private PropertyChangeSupport _changeSupport = new PropertyChangeSupport(this);
    
    /** Creates a new instance of FuzzFactory */
    public FuzzFactory() {
    }
    
    public String[] getSourceDescriptions() {
        return (String[]) _sources.keySet().toArray(new String[_sources.size()]);
    }
    
    public void addSource(FuzzSource source) {
        _sources.put(source.getDescription(), source);
        _changeSupport.firePropertyChange(SOURCES, null, null);
    }
    
    public void loadFuzzStrings(String description, InputStream inputStream) throws IOException {
        addSource(new FileSource(description, new InputStreamReader(inputStream)));
    }
    
    public void loadFuzzStrings(String description, File file) throws IOException {
        addSource(new FileSource(description, new FileReader(file)));
    }
    
    public boolean removeSource(String name) {
        boolean success = (_sources.remove(name) != null);
        _changeSupport.firePropertyChange(SOURCES, null, null);
        return success;
    }
    
    public void addRegexSource(String description, String regex) throws PatternSyntaxException {
        addSource(new RegexSource(description, regex));
    }
    
    public FuzzSource getSource(String name) {
        FuzzSource source = (FuzzSource) _sources.get(name);
        if (source == null) {
            return null;
        } else {
            return source.newInstance();
        }
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.addPropertyChangeListener(listener);
    }
    
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.removePropertyChangeListener(listener);
    }
    
    private class FileSource implements FuzzSource {
        
        private String _description;
        private String[] _items;
        private int _index = 0;
        
        public FileSource(String description, Reader reader) throws IOException {
            _description = description;
            BufferedReader br = new BufferedReader(reader);
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
        
        public FuzzSource newInstance() {
            return new ArraySource(_description, _items);
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
        
        public FuzzSource newInstance() {
            return new ArraySource(_description, _items);
        }
        
    }
    
}
