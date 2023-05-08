FROM golang:1.19.7

RUN go install -v github.com/ramya-rao-a/go-outline@v0.0.0-20210608161538-9736a4bde949 \
  && go install -v golang.org/x/tools/gopls@latest

CMD ["/bin/bash"]