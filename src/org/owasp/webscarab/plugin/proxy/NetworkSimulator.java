/*
 * NetworkSimulator.java
 *
 * Created on May 18, 2004, 9:18 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.util.Timer;
import java.util.TimerTask;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;

/**
 *
 * @author  knoppix
 */
public class NetworkSimulator {
    
    private static Timer _timer = new Timer(true);
    private static int HZ = 2;
    
    private boolean _shared = false;
    
    private Object _readLock = null;
    private Object _writeLock = null;
    private Object _sharedLock = null;
    
    private String _name;
    
    private int _readBandwidth = 0;
    private int _writeBandwidth = 0;
    private int _sharedBandwidth = 0;
    
    private int _readAvailable = 0;
    private int _writeAvailable = 0;
    private int _sharedAvailable = 0;
    
    private int _latency;
    
    /** Creates a new instance of NetworkSimulator */
    public NetworkSimulator(String name, int latency, int readBandwidth, int writeBandwidth) {
        _readLock = new Object();
        _writeLock = new Object();
        
        _name = name;
        _shared = false;
        _latency = latency;
        _readBandwidth = readBandwidth;
        _writeBandwidth = writeBandwidth;
        _timer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                refreshBandwidth();
            }
        }, 0, 1000 / HZ);
    }
    
    public NetworkSimulator(String name, int latency, int sharedBandwidth) {
        _sharedLock = new Object();
        
        _name = name;
        _shared = true;
        _latency = latency;
        _sharedBandwidth = sharedBandwidth;
        _timer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                refreshBandwidth();
            }
        }, 0, 1000 / HZ);
    }
    
    public String getName() {
        return _name;
    }
    
    private void refreshBandwidth() {
        if (_shared) {
            synchronized(_sharedLock) {
                _sharedAvailable = _sharedBandwidth / HZ;
                _sharedLock.notifyAll();
            }
        } else {
            synchronized(_readLock) {
                _readAvailable = _readBandwidth / HZ;
                _readLock.notifyAll();
            }
            synchronized(_writeLock) {
                _writeAvailable = _writeBandwidth / HZ;
                _writeLock.notifyAll();
            }
        }
    }
    
    private int reserveShared(int requested) {
        synchronized(_sharedLock) {
            if (requested == 0) {
                try {
                    _sharedLock.wait();
                } catch (InterruptedException ie) {}
                return 0;
            }
            while(_sharedAvailable == 0) {
                try {
                    _sharedLock.wait();
                } catch (InterruptedException ie) {}
            }
            int allocation = Math.min(requested, _sharedAvailable);
            _sharedAvailable -= allocation;
            return allocation;
        }
    }
    
    private int reserveRead(int requested) {
        if (_shared) {
            return reserveShared(requested);
        }
        synchronized(_readLock) {
            if (requested == 0) {
                try {
                    _readLock.wait();
                } catch (InterruptedException ie) {}
                return 0;
            }
            while(_readAvailable == 0) {
                try {
                    _readLock.wait();
                } catch (InterruptedException ie) {}
            }
            int allocation = Math.min(requested, _readAvailable);
            _readAvailable -= allocation;
            return allocation;
        }
    }
    
    private int reserveWrite(int requested) {
        if (_shared) {
            return reserveShared(requested);
        }
        synchronized(_writeLock) {
            if (requested == 0) {
                try {
                    _writeLock.wait();
                } catch (InterruptedException ie) {}
                return 0;
            }
            while(_writeAvailable == 0) {
                try {
                    _writeLock.wait();
                } catch (InterruptedException ie) {}
            }
            int allocation = Math.min(requested, _writeAvailable);
            _writeAvailable -= allocation;
            return allocation;
        }
    }
    
    public InputStream wrapInputStream(InputStream in) {
        return new NetworkSimulator.SimulatedInputStream(in);
    }
    
    public OutputStream wrapOutputStream(OutputStream out) {
        return new NetworkSimulator.SimulatedOutputStream(out);
    }
    
    private class SimulatedInputStream extends FilterInputStream {
        
        public SimulatedInputStream(InputStream in) {
            super(in);
        }
        
        public int read() throws IOException {
            int got = in.read();
            if (got < 0) return got;
            while (reserveRead(1)==0);
            return got;
        }
        
        public int read(byte[] buff, int off, int len) throws IOException {
            int allocation = 0;
            int got = in.read(buff, off, len);
            while (allocation < got) {
                allocation = allocation + reserveRead(got - allocation);
            }
            return got;
        }
        
    }
    
    private class SimulatedOutputStream extends FilterOutputStream {
        
        private boolean _started = false;
        
        public SimulatedOutputStream(OutputStream out) {
            super(out);
        }
        
        private void sleep(int period) {
            try {
                Thread.currentThread().sleep(period);
            } catch (InterruptedException ie) {}
        }
        
        public void write(byte b) throws IOException {
            if (!_started) { 
                sleep(_latency);
                _started = true;
            }
            while (reserveWrite(1)==0);
            out.write(b);
        }
        
        public void write(byte[] buff, int off, int len) throws IOException {
            if (!_started) {
                sleep(_latency);
                _started = true;
            }
            int allocation;
            while (len > 0) {
                allocation = reserveWrite(len);
                if (allocation > 0) {
                    out.write(buff, off, allocation);
                    off += allocation;
                    len -= allocation;
                }
            }
        }
        
    }
    
}
