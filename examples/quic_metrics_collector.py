from prometheus_client import start_http_server, Gauge, Counter
import psutil
import time
import socket
import threading

class QUICMetricsCollector:
    def __init__(self, metrics_port=8000, quic_port=4433):
        # Start metrics server
        start_http_server(metrics_port)
        print(f"📊 Metrics collector started on port {metrics_port}")
        
        # Server status
        self.server_running = Gauge('quic_server_up', 'Is QUIC server running (1=yes, 0=no)')
        self.server_uptime = Gauge('quic_server_uptime_seconds', 'Server uptime')
        
        # Connection tracking (simulated/estimated)
        self.connections_active = Gauge('quic_connections_active', 'Estimated active connections')
        self.connections_total = Counter('quic_connections_total', 'Total connections (estimated)')
        
        # Network stats from system
        self.bytes_sent = Counter('quic_bytes_sent_total', 'Bytes sent (from network stats)')
        self.bytes_received = Counter('quic_bytes_received_total', 'Bytes received (from network stats)')
        
        # Track process
        self.quic_port = quic_port
        self.start_time = time.time()
        self.last_bytes_sent = 0
        self.last_bytes_received = 0
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_server, daemon=True)
        self.monitor_thread.start()
        
        print("✅ Monitoring QUIC server on port", quic_port)
    
    def _get_network_stats(self):
        """Get network statistics for QUIC port"""
        total_sent = 0
        total_received = 0
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='udp')
            
            for conn in connections:
                # Check if this is our QUIC server socket
                if conn.laddr and conn.laddr.port == self.quic_port:
                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid)
                        io_counters = proc.io_counters()
                        
                        # Track bytes (this is approximate)
                        if hasattr(io_counters, 'write_bytes'):
                            total_sent += io_counters.write_bytes
                        if hasattr(io_counters, 'read_bytes'):
                            total_received += io_counters.read_bytes
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            print(f"Warning: Could not get network stats: {e}")
        
        return total_sent, total_received
    
    def _monitor_server(self):
        """Monitor server status and network traffic"""
        while True:
            # Check if server is running by checking port
            server_up = self._check_port_open(self.quic_port)
            self.server_running.set(1 if server_up else 0)
            
            # Update uptime
            self.server_uptime.set(time.time() - self.start_time)
            
            # Get network stats
            sent, received = self._get_network_stats()
            
            # Calculate delta since last check
            if self.last_bytes_sent > 0:
                delta_sent = sent - self.last_bytes_sent
                if delta_sent > 0:
                    self.bytes_sent.inc(delta_sent)
            
            if self.last_bytes_received > 0:
                delta_received = received - self.last_bytes_received
                if delta_received > 0:
                    self.bytes_received.inc(delta_received)
            
            self.last_bytes_sent = sent
            self.last_bytes_received = received
            
            # Simulate connection tracking (you can replace with real tracking)
            if server_up:
                # Simple simulation - in real setup, you'd track actual connections
                current_connections = self._estimate_connections()
                self.connections_active.set(current_connections)
            
            time.sleep(2)  # Update every 2 seconds
    
    def _check_port_open(self, port):
        """Check if QUIC port is listening"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _estimate_connections(self):
        """Estimate active connections (placeholder)"""
        # This is a simulation - in reality, you'd track actual connections
        # For now, return a simulated value
        import random
        return random.randint(0, 10)

if __name__ == "__main__":
    print("🚀 Starting QUIC Metrics Collector")
    print("This runs alongside your Hypic server")
    print("Metrics available at: http://localhost:8000/metrics")
    print()
    
    collector = QUICMetricsCollector(metrics_port=8000, quic_port=4433)
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping metrics collector...")
