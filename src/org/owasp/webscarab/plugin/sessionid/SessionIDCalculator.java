/*
 * CharacterSetCalculator.java
 *
 * Created on 17 November 2003, 04:19
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.util.NotifiableListModel;
import java.math.BigInteger;

import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

/**
 *
 * @author  rdawes
 */
public class SessionIDCalculator implements ListDataListener {
    
    private NotifiableListModel _lm;
    private static final int MAXLENGTH = 1000; // the longest cookie we can calculate
    private int[][] _charset = new int[MAXLENGTH][128];
    private int[] _charcount = new int[MAXLENGTH];
    private String[] _chars = new String[MAXLENGTH];
    private int _maxlength = 0;
    private int _lastCalculation = -1;
    private transient boolean _calculating = false;
    
    /** Creates a new instance of CharacterSetCalculator */
    public SessionIDCalculator(NotifiableListModel lm) {
        _lm = lm;
        if (_lm != null) {
            _lm.addListDataListener(this);
        }
    }
    
    // returns true if the character set was modified, requiring a recalculation
    private boolean updateCharset(String value) {
        boolean updated = false;
        // this establishes the character set per position
        // results in a two dimensional array indicating 
        // the frequency of each character at each position
        for (int i=0; i<value.length(); i++) {
            char ch = value.charAt(i);
            if (_charset[i][ch] == 0) {
                updated = true;
            }
            _charset[i][ch]++;
        }
        return updated;
    }

    private BigInteger convertStringToBigInt(String value) {
        BigInteger total = BigInteger.ZERO;
        for (int i=value.length()-1; i>=0; i--) {
            char ch = value.charAt(i);
            BigInteger val = new BigInteger(Integer.toString(_chars[i].indexOf(ch)));
            BigInteger base = new BigInteger(Integer.toString(_chars[i].length()));
            base = base.pow(value.length()-1-i);
            total = total.add(base.multiply(val));
            Thread.yield(); // to keep interactive performance acceptable
        }
        return total;
    }
    
    public void calculate() {
        _calculating = true; 
        int size = _lm.size();
        SessionID sessid;
        String value;
        BigInteger total;
        int length;
        for (int position=_lastCalculation+1; position<size; position++) {
            sessid = (SessionID) _lm.get(position);
            value = sessid.getValue();
            length = value.length();
            if (length>_maxlength) {
                _maxlength = length;
            }
            if (updateCharset(value)) {
                _lastCalculation = -1;
            }
        }
        // convert each position's character set into a string for easier manipulation
        for (int i=0; i<_maxlength; i++) {
            StringBuffer buff = new StringBuffer();
            for (char ch=32; ch<128; ch++) {
                if (_charset[i][ch]>0) {
                    buff.append(ch);
                }
            }
            _chars[i]=buff.toString();
        }
        System.err.println("Starting calculations at " + _lastCalculation);
        for (int position=_lastCalculation+1; position<size; position++) {
            sessid = (SessionID) _lm.get(position);
            value = sessid.getValue();
            length = value.length();
            sessid.setIntValue(convertStringToBigInt(value));
        }
        _lm.contentsChanged();
        _lastCalculation = size-1;
        System.err.println("Finishing calculations at " + _lastCalculation);
        _calculating = false;
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
        if (_calculating) return;
        int startPosition = e.getIndex0();
        if (startPosition > _lastCalculation + 1) {
            return;
        }
        SessionID sessid;
        String value;
        int length;
        BigInteger total;
        for (int position=e.getIndex0(); position<=e.getIndex1(); position++) {
            sessid = (SessionID) _lm.get(position);
            value = sessid.getValue();
            length = value.length();
            if (length>_maxlength) {
                _maxlength = length;
            }
            
            // this could skew the statistics slightly, if we return after the first character in the value, but we are not using them for anything anyway ;-)
            if (updateCharset(value)) {
                System.err.println("Charset was updated, aborting automatic calculation at " + position);
                return;
            }
            
            sessid.setIntValue(convertStringToBigInt(value));
            _lastCalculation = position;
            _lm.contentsChanged(position, position);
        }
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
        _lastCalculation = -1;
    }
    
}
