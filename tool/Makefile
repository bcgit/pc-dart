all: clean depends build bundle


clean:
	-rm -rf ../out


depends:
	cd ..; pub get; cd tool


build: test doc


test: depends
	@echo "********************************************************************************"
	@echo "RUNNING TESTS"
	@echo "********************************************************************************"

	dart ../test/all_tests.dart


doc: doc-api doc-impl


doc-api: depends
	@echo "********************************************************************************"
	@echo "MAKING API DOCUMENTATION"
	@echo "********************************************************************************"

	-rm -rf ../out/doc/api
	mkdir -p ../out/doc/api

	dartdoc --out=../out/doc/api \
          --include-lib=cipher \
          --include-lib=cipher.api \
          --include-lib=cipher.parameters \
          --include-lib=cipher.impl \
          --package-root=../packages \
          --no-code \
          --link-api ../lib/cipher.dart


doc-impl: depends
	@echo "********************************************************************************"
	@echo "MAKING IMPL DOCUMENTATION"
	@echo "********************************************************************************"

	-rm -rf ../out/doc/impl
	mkdir -p ../out/doc/impl

	dartdoc --out=../out/doc/impl \
          --exclude-lib=cipher.src.ufixnum \
          --exclude-lib=cipher.src.adapters.stream_cipher_adapters \
          --exclude-lib=meta \
          --exclude-lib=fixnum \
          --exclude-lib=bignum \
          --package-root=../packages \
          --no-code \
          --link-api ../lib/cipher.dart


bundle: bundle-package bundle-doc


bundle-package: test
	@echo "********************************************************************************"
	@echo "MAKING PACKAGE BUNDLE"
	@echo "********************************************************************************"

	-rm ../out/bundle/cipher.tar.gz
	mkdir -p ../out/bundle

	tar -c -z -C .. --exclude packages -f ../out/bundle/cipher.tar.gz LICENSE README.md pubspec.yaml bin/ lib/ licenses test/ tool/



bundle-doc: doc
	@echo "********************************************************************************"
	@echo "MAKING DOC BUNDLE"
	@echo "********************************************************************************"

	-rm ../out/bundle/cipher-doc.tar.gz
	mkdir -p ../out/bundle

	tar -c -z -C../out/doc -f ../out/bundle/cipher-doc.tar.gz api impl



deploy: deploy-doc deploy-pub


deploy-doc: doc
	@echo "********************************************************************************"
	@echo "DEPLOYING DOC TO GITHUB'S GH-PAGES"
	@echo "********************************************************************************"


deploy-pub: test
	@echo "********************************************************************************"
	@echo "DEPLOYING TO PUB"
	@echo "********************************************************************************"
