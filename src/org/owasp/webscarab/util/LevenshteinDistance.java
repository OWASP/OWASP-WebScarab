package org.owasp.webscarab.util;

/*
 * Calculates the Levenshtein distance between two byte arrays
 * This is great for showing which responses are similar or different
 * to others. However, it is VERY slow, O(n*m), which bogs down really
 * quickly if we start looking at sequences of a few thousand bytes :-(
 * 
 * We optimize by tokenising the input into words, and comparing those
 * 
 * An alternative might be the XDelta algorithm, see e.g. 
 * http://sourceforge.net/projects/javaxdelta/&e=10313
 * 
 * Also see a paper "A Linear Time, Constant Space Differencing Algorithm" by Burns and Long
 */

import java.util.List;
import java.util.Iterator;

public class LevenshteinDistance {
    
    private List _baseline;
    private int[] _current, _previous;
    
    public LevenshteinDistance(List baseline) {
        _baseline = baseline;
        _current = new int[_baseline.size()+1];
        _previous = new int[_baseline.size()+1];
    }
    
    public synchronized int getDistance(List target) {
        if (_baseline.size() == 0)
            return target.size();
        if (target.size() == 0)
            return _baseline.size();
        
        for (int i = 0; i < _current.length; i++) {
            _current[i] = i;
        }
        
        Iterator targIt = target.iterator();
        int j=0;
        while(targIt.hasNext()) {
            Object targObj = targIt.next();
            j++;
            
            int[] t = _previous;
            _previous = _current;
            _current = t;
            
            _current[0] = _previous[0]+1;
            
            Iterator baseIt = _baseline.iterator();
            int i=0;
            while(baseIt.hasNext()) {
                Object baseObj = baseIt.next();
                i++;
                
                int cost;
                if (baseObj.equals(targObj)) {
                  cost = 0;
                } else {
                  cost = 1;
                }
                _current[i] = Math.min(Math.min(_previous[i]+1, _current[i-1]+1), _previous[i-1] + cost);
            }
        }
        return _current[_baseline.size()];
    }

    public static void main(String[] args) {
        List baseline = new java.util.ArrayList();
        baseline.add(new Character('l'));
        baseline.add(new Character('e'));
        baseline.add(new Character('v'));
        baseline.add(new Character('e'));
        baseline.add(new Character('n'));
        baseline.add(new Character('s'));
        baseline.add(new Character('h'));
        baseline.add(new Character('t'));
        baseline.add(new Character('e'));
        LevenshteinDistance ld = new LevenshteinDistance(baseline);
        List target = new java.util.ArrayList();
        target.add(new Character('m'));
        target.add(new Character('e'));
        target.add(new Character('i'));
        target.add(new Character('l'));
        target.add(new Character('e'));
        target.add(new Character('n'));
        target.add(new Character('s'));
        target.add(new Character('t'));
        target.add(new Character('e'));
        int distance = ld.getDistance(target);
        System.out.println("Distance between \"meilenstein\" and \"levenshtein\": " + distance);
    }
}
