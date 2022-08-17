FROM golang:1.18

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./

RUN go build -o ./indefinite-studies-auth-service

EXPOSE 3000

CMD [ "./indefinite-studies-auth-service" ]