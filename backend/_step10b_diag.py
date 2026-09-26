"""Throwaway diagnostic — compile the agent module and dump lines 85-135."""
import compileall
import sys

path = r"app/agents/correlation.py"
try:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    compile(source, path, "exec")
    status = "SYNTAX-OK"
except Exception as exc:  # noqa: BLE001 - diagnostic only
    status = f"SYNTAX-ERROR: {type(exc).__name__}: {exc}"

lines = source.splitlines()
with open("_step10b_diag.txt", "w", encoding="utf-8") as out:
    out.write(status + "\n")
    out.write(f"total lines: {len(lines)}\n")
    for idx in range(84, min(136, len(lines))):
        out.write(f"{idx + 1:4d} | {lines[idx]}\n")
print("wrote _step10b_diag.txt")