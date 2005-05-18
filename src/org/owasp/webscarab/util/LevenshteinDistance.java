package org.owasp.webscarab.util;

public class LevenshteinDistance {
    
    private byte[] _baseline;
    
    public LevenshteinDistance(byte[] baseline) {
        _baseline = baseline;
    }
    
    public int getDistance(byte[] target) {
        int[] current = new int[_baseline.length+1];
        int[] previous = new int[_baseline.length+1];
        int i,j,cost;
        
        if (_baseline.length == 0)
            return target.length;
        if (target.length == 0)
            return _baseline.length;
        
        for (i = 0; i <= _baseline.length; i++) {
            current[i] = i;
        }
        
        for (i = 1; i <= _baseline.length; i++) {
            int[] t = previous;
            previous = current;
            current = t;
            
            current[0] = previous[0]+1;
            
            for (j = 1; j <= target.length; j++) {
                if (_baseline[i-1] == target[j-1]) {
                  cost = 0;
                } else {
                  cost = 1;
                }
                current[j] = Math.min(Math.min(previous[j]+1, current[j-1]+1), previous[j-1] + cost);
            }
        }
        return current[_baseline.length];
    }

    public static void main(String[] args) {
        LevenshteinDistance ld = new LevenshteinDistance("levenshtein".getBytes());
        int distance = ld.getDistance("meilenstein".getBytes());
        System.out.println("Distance between \"meilenstein\" and \"levenshtein\": " + distance);
    }
}
