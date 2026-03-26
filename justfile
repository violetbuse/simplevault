#Serve the docs server
docs-dev:
  cd ./docs && npm run dev

#Build the docs site
docs-build:
    cd ./docs && npm run build

#Publish the docs site
docs-publish:
    cd ./docs && npm run deploy

#Update the docs site
docs-update:
    cd ./docs && npm run build && npm run deploy

#Run all tests
test:
    ./run-all-tests.sh

#Build project
build:
    ./build-all.sh

#Publish project
publish:
    ./publish-all.sh