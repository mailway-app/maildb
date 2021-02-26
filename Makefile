VERSION = 1.0.0
DIST = $(PWD)/dist
FPM_ARGS =

.PHONY: clean
clean:
	rm -rf $(DIST) *.deb

$(DIST)/maildb: server.go
	mkdir -p $(DIST)
	go build -o $(DIST)/usr/local/sbin/maildb

.PHONY: deb
deb: $(DIST)/maildb
	mkdir -p $(DIST)/usr/local/lib/maildb
	fpm -n maildb -s dir -t deb --chdir=$(DIST) --version=$(VERSION) $(FPM_ARGS)

