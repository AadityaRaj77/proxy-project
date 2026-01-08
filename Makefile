.PHONY: run
run:
	python src/proxy.py --host 0.0.0.0 --port 8888 --workers 20 --blocklist config/blocked_domains.txt --log logs/proxy.log
