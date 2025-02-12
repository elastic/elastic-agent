<<<<<<< HEAD
ARG GO_VERSION=1.22.10
=======
ARG GO_VERSION=1.22.12
>>>>>>> a29af6489 ([Automation] Bump Golang version to 1.22.12 (#6700))
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

