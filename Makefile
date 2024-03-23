.PHONY: test
test:
	go test ./...

.PHONY: cleantest
cleantest:
	go clean -testcache && go test ./...