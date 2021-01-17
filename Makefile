VERSION = 1.0.0
DIST = $(PWD)/dist

.PHONY: clean
clean:
	rm -rf $(DIST) *.deb

$(DIST)/maildb: server.go
	mkdir -p $(DIST)
	go build -o $(DIST)/usr/local/sbin/maildb

.PHONY: deb
deb: $(DIST)/maildb
	fpm -n maildb -s dir -t deb --chdir=$(DIST) --version=$(VERSION)

