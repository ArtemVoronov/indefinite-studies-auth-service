FROM golang:1.21

EXPOSE 3005
EXPOSE 50051

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./

RUN go build -o ./indefinite-studies-auth-service

CMD [ "./indefinite-studies-auth-service" ]