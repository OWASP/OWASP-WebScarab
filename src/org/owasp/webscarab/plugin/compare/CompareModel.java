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
    
    private ReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    private FrameworkModel _model = null;
    
    private LevenshteinDistance _diff = null;
    
    private Map _distances = new HashMap();
    private ArrayList _compared = new ArrayList();
    
    private DiffModel _diffModel;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of CompareModel */
    public CompareModel(FrameworkModel model) {
        super(model);
        _model = model;
        _diffModel = new DiffModel(model);
    }
    
    public ConversationModel getConversationModel() {
        return _model.getConversationModel();
    }
    
    public ConversationModel getComparisonModel() {
        return _diffModel;
    }
    
    public void setBaseConversation(ConversationID id, HttpUrl url) {
        try {
            _logger.info("writeLock");
            _rwl.writeLock().acquire();
            _logger.info("done");
            _distances.clear();
            _compared.clear();
            if (id != null) {
                _logger.info("updateDiff");
                updateDifferences(id, url);
                _logger.info("done");
            }
            _logger.info("readlock");
            _rwl.readLock().acquire();
            _logger.info("done");
            _rwl.writeLock().release();
            _logger.info("fire");
            _diffModel.fireConversationsChanged();
            _logger.info("done");
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted! " + ie);
        }
    }
    
    private void updateDifferences(ConversationID id, HttpUrl url) {
        Response baseResponse = _model.getResponse(id);
        byte[] baseBytes = baseResponse.getContent();
        _diff = new LevenshteinDistance(baseBytes);
        ConversationModel cmodel = _model.getConversationModel();
        try {
            _model.readLock().acquire();
            int count = cmodel.getConversationCount(url);
            for (int i=0; i<count; i++) {
                id = cmodel.getConversationAt(url, i);
                Response response = cmodel.getResponse(id);
                byte[] bytes = response.getContent();
                _compared.add(id);
                _distances.put(id, new Integer(_diff.getDistance(bytes)));
            }
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted! " + ie);
        } finally {
            _model.readLock().release();
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
        
        public ConversationID getConversationAt(HttpUrl url, int index) {
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
        
        public int getConversationCount(HttpUrl url) {
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
        
        public int getIndexOfConversation(HttpUrl url, ConversationID id) {
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
