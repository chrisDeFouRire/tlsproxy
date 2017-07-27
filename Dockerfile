FROM golang:1.8-alpine

WORKDIR /go/src/app
COPY . .

RUN go-wrapper download   # "go get -d -v ./..."
RUN go-wrapper install    # "go install -v ./..."
VOLUME "/go/src/app/certs"

CMD ["go-wrapper", "run"] # ["app"]
