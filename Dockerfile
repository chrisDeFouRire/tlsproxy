FROM golang:1.8-alpine

WORKDIR /go/src/app
COPY . .

RUN go-wrapper download
RUN go-wrapper install
VOLUME "/go/src/app/certs"

CMD ["go-wrapper", "run"]
