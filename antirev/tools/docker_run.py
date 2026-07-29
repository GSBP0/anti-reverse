"""Docker 受控沙箱实跑(§ 三态验证):在隔离容器里跑目标二进制,拿 stdout/stderr/rc,判 right/wrong/crash/timeout。

设计(与 analyze_tools 的优雅降级一致):
- docker 缺失 → 降级(ok=False, available=False, 附回退建议),绝不抛穿主循环。
- 按魔数选平台/镜像:PE 走 wine;ELF 按 e_machine(offset18 小端)选 amd64/386/arm64(QEMU 跨架构)。
- 强隔离:--network=none 断网、--memory/--pids-limit/--cpus 限资源、-v ...:ro 只读挂载、--rm 用后即焚。
- 镜像/平台未就绪(rc==125)→ 降级回 unicorn/emulate,不阻塞求解。
"""
from __future__ import annotations
import shlex
import shutil
from pathlib import Path

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

# ELF e_machine(offset18,小端) → docker --platform
_ELF_PLATFORM = {0x3E: "linux/amd64", 0x03: "linux/386", 0xB7: "linux/arm64"}

# 容器内 runline 模板({n} 为二进制文件名):先落到 /tmp 再执行,避开只读挂载点的执行位问题。
_ELF_RUNCMD = ("install -m755 /work/{n} /tmp/b 2>/dev/null || "
               "(cp /work/{n} /tmp/b && chmod +x /tmp/b); exec /tmp/b")
_PE_RUNCMD = "cp /work/{n} /tmp/b.exe && exec wine /tmp/b.exe"

_DEGRADE_NO_DOCKER = ("docker 未安装,降级:用 emulate_function/unicorn 或 "
                      "run_python 正向重算自验")


def _select(data: bytes):
    """按魔数返回 (kind, platform, image, runcmd_template);不支持的格式/架构 → (None,None,None,None)。

    image 可以是候选元组(按序取第一个本地就绪/能拉到的)——PE 优先本机自建的 antirev-wine:local
    (docker hub 的 wine 镜像本机 registry 拉不到;见 docker/wine.Dockerfile 的自建说明)。
    """
    if data[:2] == b"MZ":
        return ("PE", "linux/amd64", ("antirev-wine:local", "scottyhardy/docker-wine"), _PE_RUNCMD)
    if data[:4] == b"\x7fELF":
        machine = int.from_bytes(data[18:20], "little")
        plat = _ELF_PLATFORM.get(machine)
        if plat:
            # 多候选:本地有哪个用哪个,都没有再逐个尝试拉。单一镜像时一旦本地被清掉
            # 且 registry 不通,ELF 实跑就整个失效(用户误删镜像后实际发生过)。
            # amd64 经 docker 的 Rosetta/QEMU 可在 arm64 主机跨架构跑(实测 uname -m=x86_64)
            return ("ELF", plat,
                    ("debian:12", "debian:stable-slim", "ubuntu:22.04", "ubuntu:20.04", "busybox:1.36"),
                    _ELF_RUNCMD)
    return (None, None, None, None)


# "程序压根没跑起来"的迹象 —— 必须在关键词判决**之前**识别:
# wine 跑 32 位 PE 会打 "Application could not be started / ShellExecuteEx failed",
# 其中 "failed" 命中 FAIL_KEYWORDS → 被判成 verdict=wrong,等于告诉模型"你的 flag 错了",
# 会让它把**正确答案**当错的丢掉(R30 实测 7/9 次 docker_run 都栽在这)。
_NOT_RUN_SIGNS = (
    "could not be started", "shellexecuteex failed", "wine: cannot find",
    "exec format error", "cannot execute binary file", "no such file or directory",
    "permission denied", "not a valid win32 application",
)


def _verdict(text, rc, timed_out) -> str:
    """判决:timeout / not_run(没跑起来,**非对错**) / right / wrong / crash / ok / unknown。"""
    if timed_out:
        return "timeout"
    low = (text or "").lower()
    if any(s in low for s in _NOT_RUN_SIGNS):
        return "not_run"
    if any(k in low for k in config.SUCCESS_KEYWORDS):
        return "right"
    if any(k in low for k in config.FAIL_KEYWORDS):
        return "wrong"
    # 139/134 = docker 上报的 128+SIGSEGV/SIGABRT;-11/-6/rc<0 = 直接被信号杀
    if rc in (139, -11, 134, -6) or (isinstance(rc, int) and rc < 0):
        return "crash"
    if rc == 0:
        return "ok"
    return "unknown"


# 每种判决给 agent 的下一步建议(治 verdict=unknown/ok 的误导:agent 分不清"没验证成功"与"flag 错")
_ADVICE = {
    "right": "✓ 程序判定正确(命中成功词)——硬验证,直接 submit_flag",
    "wrong": "✗ 程序判定错误(命中失败词)——别提交,回查算法/密钥/字节序重解",
    "crash": "程序崩溃(段错误/abort)——喂的输入格式可能不对,或非此验证方式",
    "timeout": "程序超时(死循环/在等更多输入)——可能不是一次性 stdin 比对型",
    "not_run": ("⚠ **程序没跑起来**(不是 flag 错!):32 位 PE 需 wine32(本镜像只有 wine64)/格式不被支持。"
                "**别据此否定你的候选 flag**——改用 emulate_function 跑二进制自身逻辑,或 run_python 正向重算自验"),
    "ok": "程序正常退出但**没输出对错词**——多半不是'读 stdin 比对 flag'型,或该看 stdout 里的真实输出;**别当验证通过**,改正向重算(re-encrypt==密文)自验",
    "unknown": "程序 rc≠0 且无对错反馈——**没验证成功**(输入方式可能不对);别依赖此结果,改正向重算自验或 emulate_function 观测",
}


def _ensure_image(image) -> bool:
    """确保镜像本地就绪:已存在→True;否则 docker pull(独立长 timeout,不塞进运行 timeout)。

    拉取失败/超时→False,让上层优雅降级——绝不把'镜像还没拉到'误报成'程序跑超时'
    (这正是 docker_run 之前对任何未预拉镜像必然 timeout 的根因)。
    """
    insp = run_isolated(["docker", "image", "inspect", image], timeout=15)
    if insp.returncode == 0:
        return True
    pull = run_isolated(["docker", "pull", image],
                        timeout=getattr(config, "DOCKER_PULL_TIMEOUT", 300))
    return pull.returncode == 0


def docker_run(binary, stdin_hex="", args=None, timeout=None) -> dict:
    """在受控 docker 沙箱里实跑 binary,喂 stdin(hex 串),返回三态验证结果。

    docker/镜像/平台任一未就绪都优雅降级(附回退 unicorn/emulate 的建议),绝不阻塞主循环。
    """
    if not shutil.which("docker"):
        return {"ok": False, "available": False, "error": _DEGRADE_NO_DOCKER}

    binpath = Path(binary).resolve()
    try:
        data = binpath.read_bytes()
    except OSError as e:
        return {"ok": False, "available": True, "error": f"读不到二进制: {e!r}"}

    kind, plat, image, runcmd = _select(data)
    if kind is None:
        return {"ok": False, "available": True,
                "error": "不支持的格式(非 PE/ELF 或架构不支持),"
                         "降级:用 emulate_function/unicorn 或 run_python 正向重算自验"}

    # 镜像未就绪→按候选序找一个能用的(本地已有优先,其次拉);都不行就诚实降级,不让拉取耗时被算成程序超时
    candidates = image if isinstance(image, tuple) else (image,)
    image = next((c for c in candidates if _ensure_image(c)), None)
    if image is None:
        extra = (f"(PE 需 wine 镜像:本机自建 `docker build --platform linux/amd64 "
                 f"--build-arg http_proxy=http://http.docker.internal:3128 -t antirev-wine:local "
                 f"-f docker/wine.Dockerfile .`)" if kind == "PE" else "")
        return {"ok": False, "available": True,
                "error": f"docker 镜像 {'/'.join(candidates)} 均未就绪(本地无且拉取失败){extra},"
                         "降级:用 emulate_function/unicorn 或 run_python 正向重算自验"}

    # shlex.quote 文件名:含空格时 /work/'my file' 在 shell 里仍拼成单个路径参数
    runline = runcmd.format(n=shlex.quote(binpath.name))
    if args:
        runline += " " + " ".join(shlex.quote(str(a)) for a in args)

    cmd = [
        "docker", "run", "--rm", "-i",      # -i 必需:否则容器 stdin 不挂载,喂进去的 flag 根本到不了程序
        "--network=none",
        "--platform", plat,
        "--memory", "256m",
        "--pids-limit", "128",
        "--cpus", "1",
        "-v", f"{binpath.parent}:/work:ro",
        "-w", "/work",
        image,
        "sh", "-c", runline,
    ]

    input_text = bytes.fromhex(stdin_hex).decode("latin1") if stdin_hex else None
    r = run_isolated(cmd, timeout=timeout or getattr(config, "DOCKER_TIMEOUT", 45),
                     input_text=input_text)

    # rc==125:docker 自身报错(镜像拉取失败/平台不支持),不是目标程序退出码
    if r.returncode == 125 and not r.timed_out:
        return {"ok": False, "available": True,
                "error": "docker 镜像/平台未就绪(rc=125),降级回 unicorn/emulate 自验: "
                         + (r.stderr or r.stdout).strip()[:200]}

    verdict = _verdict(r.stdout + "\n" + r.stderr, r.returncode, r.timed_out)
    return {
        "ok": True,
        "available": True,
        "kind": kind,
        "image": image,
        "platform": plat,
        "returncode": r.returncode,
        "timed_out": r.timed_out,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "verdict": verdict,
        "advice": _ADVICE.get(verdict, ""),
    }
