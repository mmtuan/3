"""
Deobfuscator v5 - dùng sys.addaudithook (Python 3.8+)
Audit hook hoạt động ở tầng C, code không phát hiện được.
"""
import sys, base64, lzma, marshal, dis, zlib, io, types, os

def log(msg): print(f"[*] {msg}", file=sys.stderr, flush=True)

# ── Giải mã outer layer ───────────────────────────────────────────────────────

def decode_outer(path: str) -> types.CodeType:
    with open(path, "rb") as f:
        content = f.read()
    # Hỗ trợ cả .py và .pyc
    if path.endswith(".pyc"):
        return marshal.loads(content[16:])
    idx = content.index(b"b85decode(b'")
    start = idx + len(b"b85decode(b'")
    end = start
    while end < len(content):
        if content[end:end+1] == b"'": break
        end += 1
    blob = content[start:end]
    log(f"Blob: {len(blob):,} bytes")
    decoded = base64.b85decode(blob[::-1])
    log(f"Sau base85: {len(decoded):,} bytes")
    decompressed = lzma.decompress(decoded)
    log(f"Sau LZMA: {len(decompressed):,} bytes")
    code = marshal.loads(decompressed)
    log(f"Marshal OK: {code.co_name}")
    return code

# ── Audit Hook - hoạt động ở tầng C, không bị phát hiện ─────────────────────

_captured: list = []
_audit_active = False

def _audit_hook(event, args):
    if not _audit_active:
        return
    try:
        if event == "exec":
            obj = args[0] if args else None
            if isinstance(obj, types.CodeType):
                # Chỉ lấy code object lớn (payload thật)
                if len(obj.co_consts) > 15 or any(hasattr(c, 'co_name') for c in obj.co_consts):
                    _captured.append(("exec:code", obj))
                    log(f"  ✅ audit:exec bắt được code object (consts={len(obj.co_consts)})")
            elif isinstance(obj, str) and len(obj) > 200:
                _captured.append(("exec:str", obj))
                log(f"  ✅ audit:exec bắt được string ({len(obj)} chars)")

        elif event == "eval" or event == "compile":
            obj = args[0] if args else None
            if isinstance(obj, str) and len(obj) > 200:
                _captured.append((f"{event}:str", obj))
                log(f"  ✅ audit:{event} bắt được string ({len(obj)} chars)")
    except Exception:
        pass

# Đăng ký audit hook (không thể gỡ bỏ, chỉ thực hiện 1 lần)
sys.addaudithook(_audit_hook)

# ── Chạy code trong môi trường thật ─────────────────────────────────────────

def run_real(code_obj: types.CodeType):
    global _audit_active
    log("Bắt đầu chạy code (audit hook đang giám sát)...")
    _audit_active = True
    try:
        fake_globals = {
            "__name__": "__main__",
            "__file__": "target.py",
            "__builtins__": __builtins__,
        }
        exec(code_obj, fake_globals)
    except ZeroDivisionError:
        log("  ⚠️  ZeroDivisionError (kỹ thuật anti-debug bình thường)")
    except SystemExit:
        log("  ⚠️  SystemExit")
    except Exception as e:
        log(f"  ⚠️  {type(e).__name__}: {e}")
    finally:
        _audit_active = False
    log(f"Xong: {len(_captured)} payload bắt được")
    return list(_captured)

# ── Giải mã strings từ bytes constants ───────────────────────────────────────

def decode_bytes_const(b: bytes) -> str | None:
    try:
        rev = b[::-1]
        if rev[:1] == b'\x78':
            return zlib.decompress(rev).decode('utf-8', errors='replace')
    except: pass
    try: return zlib.decompress(b).decode('utf-8', errors='replace')
    except: pass
    try:
        s = base64.b85decode(b)
        return zlib.decompress(s).decode('utf-8', errors='replace')
    except: pass
    return None

def collect_strings(co, results=None, seen=None):
    if results is None: results = []
    if seen is None: seen = set()
    if id(co) in seen: return results
    seen.add(id(co))
    for c in co.co_consts:
        if isinstance(c, bytes) and len(c) > 3:
            s = decode_bytes_const(c)
            if s and len(s.strip()) > 1:
                results.append(s)
        elif isinstance(c, str) and len(c) > 2:
            if all(32 <= ord(ch) < 127 for ch in c) and c.strip():
                results.append(c)
        elif hasattr(c, 'co_name'):
            collect_strings(c, results, seen)
    return results

# ── Disassemble / decompile ───────────────────────────────────────────────────

def disassemble(co: types.CodeType) -> str:
    buf = io.StringIO()
    old = sys.stdout; sys.stdout = buf
    try: dis.dis(co)
    finally: sys.stdout = old
    return buf.getvalue()

def try_decompile(co: types.CodeType) -> str | None:
    for pkg in ("decompile", "uncompyle6.main"):
        try:
            if pkg == "decompile":
                import decompile  # type: ignore
                buf = io.StringIO()
                decompile.decompile_code(co, buf)
                return buf.getvalue()
            else:
                import uncompyle6.main as u6  # type: ignore
                buf = io.StringIO()
                u6.decompile_code(sys.version_info[:2], co, buf)
                return buf.getvalue()
        except: pass
    return None

# ── Ghi output ───────────────────────────────────────────────────────────────

def write_output(path, outer_co, captured):
    with open(path, "w", encoding="utf-8") as f:

        f.write("=" * 70 + "\n")
        f.write("PHẦN 1: STRINGS GIẢI MÃ TỪ LỚP NGOÀI\n")
        f.write("=" * 70 + "\n\n")
        for s in collect_strings(outer_co):
            f.write(f"  {repr(s)}\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 2: PAYLOAD BẮT ĐƯỢC (AUDIT HOOK)\n")
        f.write("=" * 70 + "\n\n")

        if not captured:
            f.write("⚠️  Không bắt được payload.\n")
            f.write("    Có thể code dùng cách gọi exec khác (ctypes, import C ext).\n")
            f.write("    Xem Phần 3 để đọc bytecode.\n")
        else:
            for i, (kind, obj) in enumerate(captured):
                f.write(f"\n--- [{i+1}] {kind} ---\n")
                if isinstance(obj, str):
                    f.write(obj[:5000] + "\n")
                elif isinstance(obj, types.CodeType):
                    src = try_decompile(obj)
                    if src:
                        f.write("# ✅ Decompile thành công:\n" + src + "\n")
                    else:
                        f.write("# Bytecode:\n" + disassemble(obj) + "\n")
                    inner = collect_strings(obj)
                    if inner:
                        f.write("\n# Strings trong payload:\n")
                        for s in inner: f.write(f"#   {repr(s)}\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write("PHẦN 3: BYTECODE LỚP NGOÀI\n")
        f.write("=" * 70 + "\n\n")
        src = try_decompile(outer_co)
        f.write(src if src else disassemble(outer_co))

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Dùng: python deob.py <input.py hoặc .pyc> [output.txt]")
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "output.txt"
    log(f"Xử lý: {inp}")
    outer_co = decode_outer(inp)
    captured = run_real(outer_co)
    write_output(out, outer_co, captured)
    log(f"Xong → {out}")

if __name__ == "__main__":
    main()
