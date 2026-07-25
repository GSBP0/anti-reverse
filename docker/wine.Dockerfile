# docker_run 的 PE 实跑镜像(本地自建)。
#
# 为什么自建:本机 Docker daemon 拉不到 docker hub 上的 wine 镜像(registry 超时),
# 但容器经 Docker Desktop 代理 http.docker.internal:3128 能访问 apt 源 → 用本地 debian:12 装 wine。
#
# 构建(必须带代理 build-arg,否则 apt 不通):
#   docker build --platform linux/amd64 \
#     --build-arg http_proxy=http://http.docker.internal:3128 \
#     --build-arg https_proxy=http://http.docker.internal:3128 \
#     -t antirev-wine:local -f docker/wine.Dockerfile .
#
# 覆盖 PE64(amd64);PE32(i386) 在 Apple Silicon 上受 Rosetta 限制,失败则降级 emulate。
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive \
    WINEDEBUG=-all \
    WINEPREFIX=/wine

# 只装 64 位 wine:覆盖 PE64(题库 21/32)。32 位 PE 不在支持范围(用户确认无需),
# 真要支持得再加 `dpkg --add-architecture i386 + wine32:i386`(依赖约 200MB,本机代理下极慢)。
RUN apt-get update \
    && apt-get install -y --no-install-recommends wine wine64 \
    && rm -rf /var/lib/apt/lists/*

# 预初始化 wine prefix,免每次实跑现建(慢且会打日志干扰 stdout 判决)
RUN wineboot --init > /dev/null 2>&1 || true
