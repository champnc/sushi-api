# FROM go:1.21.4-alpine3.18

# WORKDIR /code
# COPY . .
# EXPOSE 1321
# CMD [ "go", "run", "main.go" ]

FROM golang:1.21.4-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY *.go ./

RUN go build -o /main

EXPOSE 8000

CMD ["/main"]