FROM golang:1.21.6-bullseye as golang

WORKDIR /app
COPY . .

RUN go mod download
RUN go mod verify

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /main .

FROM gcr.io/distroless/static-debian11

COPY --from=golang /main .

ENTRYPOINT [ "./main" ]
