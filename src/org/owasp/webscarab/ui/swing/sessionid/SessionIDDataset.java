/*
 * SessionIDDataset.java
 *
 * Created on 17 November 2003, 02:08
 */

package org.owasp.webscarab.ui.swing.sessionid;

import org.owasp.webscarab.plugin.sessionid.SessionID;

import org.jfree.data.AbstractSeriesDataset;
import org.jfree.data.XYDataset;
import org.jfree.data.SeriesChangeEvent;

import javax.swing.ListModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;
import java.math.BigInteger;

/**
 *
 * @author  rdawes
 */
public class SessionIDDataset extends AbstractSeriesDataset implements XYDataset, ListDataListener {
    
    ListModel _lm;
    
    /** Creates a new instance of SessionIDDataset */
    public SessionIDDataset(ListModel lm) {
        _lm = lm;
        if (lm !=null) {
            _lm.addListDataListener(this);
        }
    }
    
    public int getSeriesCount() {
        return 1;
    }    

    public String getSeriesName(int param) {
        return "Cookie value";
    }
    
    public int getItemCount(int series) {
        return _lm == null ? 0 : _lm.getSize();
    }
    
    public Number getXValue(int series, int item) {
        SessionID sessid = (SessionID) _lm.getElementAt(item);
        return new Long(sessid.getDate().getTime());
    }
    
    public Number getYValue(int series, int item) {
        SessionID sessid = (SessionID) _lm.getElementAt(item);
        BigInteger bi = sessid.getIntValue();
        if (bi == null) {
            return new Float(0);
        } else {
            return new Float(bi.floatValue());
        }
    }
    
    /**
     * Sent when the contents of the list has changed in a way
     * that's too complex to characterize with the previous
     * methods. For example, this is sent when an item has been
     * replaced. Index0 and index1 bracket the change.
     *
     * @param e  a <code>ListDataEvent</code> encapsulating the
     *    event information
     *
     */
    public void contentsChanged(ListDataEvent e) {
        seriesChanged(new SeriesChangeEvent(this));
    }
    
    /**
     * Sent after the indices in the index0,index1
     * interval have been inserted in the data model.
     * The new interval includes both index0 and index1.
     *
     * @param e  a <code>ListDataEvent</code> encapsulating the
     *    event information
     *
     */
    public void intervalAdded(ListDataEvent e) {
        seriesChanged(new SeriesChangeEvent(this));
    }
    
    /** Sent after the indices in the index0,index1 interval
     * have been removed from the data model.  The interval
     * includes both index0 and index1.
     *
     * @param e  a <code>ListDataEvent</code> encapsulating the
     *    event information
     *
     */
    public void intervalRemoved(ListDataEvent e) {
        seriesChanged(new SeriesChangeEvent(this));
    }
    
}
