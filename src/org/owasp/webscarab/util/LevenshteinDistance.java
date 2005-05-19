package org.owasp.webscarab.util;


/*
 * Calculates the Levenshtein distance between two byte arrays
 * This is great for showing which responses are similar or different
 * to others. However, it is VERY slow, O(n*m), which bogs down really
 * quickly if we start looking at sequences of a few thousand bytes :-(
 *
 * An alternative might be the XDelta algorithm, see e.g. 
 * http://sourceforge.net/projects/javaxdelta/&e=10313
 * 
 * Also see a paper "A Linear Time, Constant Space Differencing Algorithm" by Burns and Long
 */

import java.util.logging.Logger;
import java.util.logging.Level;

public class LevenshteinDistance {
    
    private byte[] _baseline;
    private int[] _current, _previous;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    public LevenshteinDistance(byte[] baseline) {
        _baseline = baseline;
        _current = new int[_baseline.length+1];
        _previous = new int[_baseline.length+1];
    }
    
    public synchronized int getDistance(byte[] target) {
        int i,j,cost;
        
        if (_baseline.length == 0)
            return target.length;
        if (target.length == 0)
            return _baseline.length;
        
        for (i = 0; i <= _baseline.length; i++) {
            _current[i] = i;
        }
        
        _logger.info("Comparing " + _baseline.length + " and " + target.length);
        
        for (i = 1; i <= _baseline.length; i++) {
            int[] t = _previous;
            _previous = _current;
            _current = t;
            
            _current[0] = _previous[0]+1;
            
            for (j = 1; j <= target.length; j++) {
                if (_baseline[i-1] == target[j-1]) {
                  cost = 0;
                } else {
                  cost = 1;
                }
                _current[i] = Math.min(Math.min(_previous[i]+1, _current[i-1]+1), _previous[i-1] + cost);
            }
        }
        _logger.info("done");
        return _current[_baseline.length];
    }

    public static void main(String[] args) {
        LevenshteinDistance ld = new LevenshteinDistance("levenshtein".getBytes());
        int distance = ld.getDistance("meilenstein".getBytes());
        System.out.println("Distance between \"meilenstein\" and \"levenshtein\": " + distance);
    }
}
