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

# 代理必须**内联写在 RUN 里**:~/.docker/config.json 的 proxies.default(常是本机 Clash
# 之类的 127.0.0.1:7890)会被 Docker 自动注入构建容器并压过 --build-arg,而 127.0.0.1 在
# 容器内指向容器自己 → apt 必然 "Connection refused"。内联 env 优先级最高,且不落进最终镜像。
ARG APT_PROXY=http://http.docker.internal:3128

# 只装 64 位 wine:覆盖 PE64(题库 21/32)。32 位 PE 不在支持范围(用户确认无需),
# 真要支持得再加 `dpkg --add-architecture i386 + wine32:i386`(依赖约 200MB,本机代理下极慢)。
RUN export http_proxy=$APT_PROXY https_proxy=$APT_PROXY \
    && apt-get update -o Acquire::Retries=5 \
    # 同一 RUN 内重试:已下好的 .deb 留在 /var/cache/apt/archives,每轮只补缺失的。
    # 代理对大包(libwine ~250MB)会中途 Connection failed,单次必失败,分批攒才能成。
    && for i in 1 2 3 4 5 6 7 8; do \
         apt-get install -y --no-install-recommends \
           -o Acquire::Retries=5 -o Acquire::http::Timeout=60 \
           -o Acquire::Queue-Host::Limit=1 wine wine64 && break || \
         { echo "== retry $i =="; sleep 5; }; \
       done \
    && dpkg -l wine64 | grep -q '^ii' \
    && rm -rf /var/lib/apt/lists/*

# 预初始化 wine prefix,免每次实跑现建(慢且会打日志干扰 stdout 判决)
RUN wineboot --init > /dev/null 2>&1 || true
