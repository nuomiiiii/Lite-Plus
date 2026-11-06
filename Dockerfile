FROM alpine:3.21

WORKDIR /app

# Docker buildx 会在构建时自动填充这些变量
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata

COPY --chmod=755 Lite-${TARGETOS}-${TARGETARCH} /app/Lite

ENV GIN_MODE=release
ENV LITE_DEPLOYMENT=docker
ENV TZ=Asia/Shanghai
ENV GODEBUG=disablethp=1

EXPOSE 28777 37888

CMD ["/app/Lite", "server"]
