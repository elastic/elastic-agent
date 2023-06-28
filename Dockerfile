ARG GO_VERSION=1.19.10
FROM golang:${GO_VERSION}


RUN GO111MODULE=off go get github.com/magefile/mage
ENV GO111MODULE=on
COPY . /elastic-agent
WORKDIR /elastic-agent
RUN go mod tidy
USER root
