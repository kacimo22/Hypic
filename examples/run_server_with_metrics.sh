echo "Starting QUIC server with metrics..."

# Terminal 1: Start metrics collector
python3 quic_metrics_collector.py &
METRICS_PID=$!

# Terminal 2: Start your actual server
echo "Starting Hypic server..."
cd /home/hitkac/projects/quic-test/Hypic
python3 examples/http3_server.py --catalyst-config /home/hitkac/projects/quic-test/Hypic/catalyst_server_config.json

# When server stops, also stop metrics
kill $METRICS_PID 2>/dev/null
echo "Server and metrics stopped"