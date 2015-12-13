#!/usr/bin/make -f

pit: cmd/pit/main.go
	go get -u -ldflags="-X sshpit.Version=$(shell pword)" .
	go get -u ./cmd/pit
	mv $(shell which pit) .

Dockerfile:
	docker build -t ilowe/pitserver .
	
docker: pit Dockerfile

publish: pit
	scp pit helium:/sbin/pit

remoterun:
	ssh -t helium pit

run:
	docker run -ti -v $(shell pwd)/logs:/logs -p 2202:22 -v /var/run/docker.sock:/var/run/docker.sock ilowe/pitserver

.PHONY: Dockerfile