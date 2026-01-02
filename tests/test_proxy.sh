echo "Simple GET via proxy (example.com):"
curl -x http://localhost:8888 http://example.com -I

echo "Blocked host test (blocked_domains.txt should contain example.com or testsite):"
curl -x http://localhost:8888 http://example.com -i

echo "HTTPS via CONNECT:"
curl -x http://localhost:8888 https://example.com -I
