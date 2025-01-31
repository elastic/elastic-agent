<<<<<<< HEAD
ARG GO_VERSION=1.22.9
=======
ARG GO_VERSION=1.22.11
>>>>>>> 3145177fd ([Automation] Bump Golang version to 1.22.11 (#6663))
FROM circleci/golang:${GO_VERSION}


ARG TEST_RESULTS=/tmp/test-results

RUN mkdir -p ${TEST_RESULTS} && mkdir -p ./code
RUN go get github.com/magefile/mage

ENV GO111MODULE=on
WORKDIR ./code
#COPY --chown=circleci:circleci . .
COPY . .
VOLUME "/tmp" "dev-tools/mage/build/distributions"
USER root

