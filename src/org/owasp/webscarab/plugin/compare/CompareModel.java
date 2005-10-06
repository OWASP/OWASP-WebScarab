/*
 * CompareModel.java
 *
 * Created on 18 May 2005, 05:33
 */

package org.owasp.webscarab.plugin.compare;

import EDU.oswego.cs.dl.util.concurrent.Sync;
import EDU.oswego.cs.dl.util.concurrent.ReadWriteLock;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.AbstractConversationModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.AbstractPluginModel;

import org.owasp.webscarab.util.LevenshteinDistance;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

import java.util.Collections;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 *
 * @author  rogan
 */
public class CompareModel extends AbstractPluginModel {
    
    private FrameworkModel _model = null;
    
    private LevenshteinDistance _diff = null;
    
    private Map _distances = new HashMap();
    private ArrayList _compared = new ArrayList();
    
    private DiffModel _diffModel;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of CompareModel */
    public CompareModel(FrameworkModel model) {
        _model = model;
        _diffModel = new DiffModel(model);
    }
    
    public ConversationModel getConversationModel() {
        return _model.getConversationModel();
    }
    
    public ConversationModel getComparisonModel() {
        return _diffModel;
    }
    
    public void clearConversations() {
        try {
            _rwl.writeLock().acquire();
            _distances.clear();
            _compared.clear();
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            _diffModel.fireConversationsChanged();
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted! " + ie);
        }
    }
    
    public void setDistance(ConversationID id, int distance) {
        try {
            _rwl.writeLock().acquire();
            _distances.put(id, new Integer(distance));
            int insert = Collections.binarySearch(_compared, id);
            if (insert < 0) {
                _compared.add(-insert-1, id);
            }
            _logger.info("Adding conversation " + id + " distance " + distance + " at " + insert);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            if (insert < 0) 
                _diffModel.fireConversationAdded(id, -insert-1);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted! " + ie);
        }
    }
    
    public Integer getDistance(ConversationID id) {
        try {
            _rwl.readLock().acquire();
            return (Integer) _distances.get(id);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted! " + ie);
            return null;
        } finally {
            _rwl.readLock().release();
        }
    }
    
    private class DiffModel extends AbstractConversationModel {
        
        public DiffModel(FrameworkModel model) {
            super(model);
        }
        
        public ConversationID getConversationAt(int index) {
            try {
                _rwl.readLock().acquire();
                return (ConversationID) _compared.get(index);
            } catch (InterruptedException ie) {
                _logger.warning("Interrupted! " + ie);
                return null;
            } finally {
                _rwl.readLock().release();
            }
        }
        
        public int getConversationCount() {
            try {
                _rwl.readLock().acquire();
                return _compared.size();
            } catch (InterruptedException ie) {
                _logger.warning("Interrupted! " + ie);
                return -1;
            } finally {
                _rwl.readLock().release();
            }
        }
        
        public int getIndexOfConversation(ConversationID id) {
            try {
                _rwl.readLock().acquire();
                return Collections.binarySearch(_compared, id);
            } catch (InterruptedException ie) {
                _logger.warning("Interrupted! " + ie);
                return -1;
            } finally {
                _rwl.readLock().release();
            }
        }
        
        public Sync readLock() {
            return _rwl.readLock();
        }
        
        public void fireConversationsChanged() {
            super.fireConversationsChanged();
        }
        
        public void fireConversationAdded(ConversationID id, int position) {
            super.fireConversationAdded(id, position);
        }
        
    }
    
}
