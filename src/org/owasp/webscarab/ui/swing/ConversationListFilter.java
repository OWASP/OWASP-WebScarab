/*
 * ConversationListFilter.java
 *
 * Created on February 6, 2004, 8:51 AM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.ListModel;
import javax.swing.AbstractListModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

import org.owasp.webscarab.model.Conversation;

/**
 *
 * @author  rdawes
 */
public class ConversationListFilter extends AbstractListModel {
    
    private int _size = 0;
    private int[] _forward = new int[0];
    private int[] _backward = new int[0];
    private String _url = null;
    private ListModel _lm = null;
    private ConversationListFilter _me;
    private ListDataListener _listener;
    
    /** Creates a new instance of ConversationListFilter */
    public ConversationListFilter(ListModel list) {
        _lm = list;
        _me = this;
        new ConversationListener(_lm);
        resizeMaps();
        buildMappings();
    }
    
    public void setURL(String url) {
        _url = url;
        System.out.println("URL is now " + url);
        buildMappings();
        fireContentsChanged(this, 0, _size);
    }
    
    private void resizeMaps() {
        int size = _lm.getSize();
        if (size >= _forward.length) {
            if (size > 50) {
                size = (int) Math.round(size * 1.2);
            } else {
                size = size + 10;
            }
        } else {
            return;
        }
        int[] forward = new int[size];
        System.arraycopy(_forward, 0, forward, 0, _forward.length);
        _forward = forward;
        int[] backward = new int[size];
        System.arraycopy(_backward, 0, backward, 0, _backward.length);
        _backward = backward;
    }
    
    private void buildMappings() {
        if (_url == null) {
            _size = _lm.getSize();
            for (int i=0; i<_size; i++) {
                _forward[i] = i;
                _backward[i] = i;
            }
        } else {
            Conversation c;
            int size = _lm.getSize();
            _size = 0;
            for (int i=0; i<size; i++) {
                c = (Conversation) _lm.getElementAt(i);
                if (_url.equals(c.getProperty("URL"))) {
                    _forward[i] = _size;
                    _backward[_size] = i;
                    _size++;
                } else {
                    _forward[i] = -1;
                }
            }
        }
    }
    
    
    public Object getElementAt(int index) {
        if (index>_size) {
            throw new IndexOutOfBoundsException("Not that many elements!");
        }
        return _lm.getElementAt(_backward[index]);
    }
    
    public int getSize() {
        return _size;
    }
    
    private class ConversationListener implements ListDataListener {
        
        public ConversationListener(ListModel lm) {
            lm.addListDataListener(this);
        }
        
        public void contentsChanged(ListDataEvent e) {
            resizeMaps();
            buildMappings();
            _me.fireContentsChanged(_me, 0, _size);
        }
        
        public void intervalAdded(ListDataEvent e) {
            resizeMaps();       // FIXME - this is very inefficient. Surely we can do this by just appending to the list somehow?
            buildMappings();
            _me.fireContentsChanged(_me, 0, _size);
        }
        
        public void intervalRemoved(ListDataEvent e) {
            resizeMaps();
            buildMappings();
            _me.fireContentsChanged(_me, 0, _size);
        }
        
    }
}
