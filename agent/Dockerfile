FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go vet ./... && CGO_ENABLED=0 go build -o /agent .

FROM gcr.io/distroless/static
COPY --from=build /agent /agent
ENTRYPOINT ["/agent"]
