"""E2 工具链单测(纯离线,不联网、不依赖样本)。"""
from antirev.tools.toolchain import pyinstxtract, dotnet_info, dotnet_cil


def test_pyinstxtract_non_pyinstaller(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 200)
    r = pyinstxtract(str(f))
    assert r["ok"] is False and "PyInstaller" in r["error"]   # 优雅降级不抛


def test_dotnet_info_non_dotnet(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"MZ" + b"\x00" * 300)
    assert dotnet_info(str(f))["ok"] is False                # 非 .NET 降级不抛


def test_dotnet_cil_graceful(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"MZ" + b"\x00" * 300)
    assert dotnet_cil(str(f), "Main")["ok"] is False         # 不抛
