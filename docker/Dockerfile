FROM alpine as build-env
RUN apk add --no-cache build-base
WORKDIR /app
COPY . .
RUN make hello

FROM alpine
COPY --from=build-env /app/hello /app/hello
WORKDIR /app
USER root:root
CMD ["/app/hello"]
