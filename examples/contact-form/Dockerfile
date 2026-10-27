FROM golang:1.26.10@sha256:24a707af49702fa44f02785475d02fb752f6982d3e9c0afb7696e1f0204e7ce9 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /contact-form . \
 && mkdir /data-empty

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /contact-form /contact-form
# Peek mounts a named volume at /data; an owned, empty directory in the image
# makes the volume writable by the non-root user (uid 65532).
COPY --from=build --chown=65532:65532 /data-empty /data
USER 65532:65532
ENTRYPOINT ["/contact-form"]
