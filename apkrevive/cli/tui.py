"""
tui.py - Terminal UI and Rich formatting components for ApkRevive.
Provides banner rendering, diagnostic summary tables, and byte-alignment ladders
with automatic fallback to plain text if rich is unavailable or non-interactive.
"""

import io
import os
import sys
from typing import Any, Dict, List, Optional, Union

try:
    import rich
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False
    box = None  # type: ignore[assignment]
    Console = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]


def _is_interactive() -> bool:
    if os.environ.get("NO_COLOR") == "1":
        return False
    if os.environ.get("FORCE_COLOR") == "1":
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def render_verdict_banner(
    verdict: str,
    reason: str,
    install_method: Optional[str] = None,
    force_rich: Optional[bool] = None,
) -> str:
    """
    Renders a colorful status banner for a triage or revive verdict.
    Falls back cleanly to plain text if rich is not available or non-interactive.
    """
    use_rich = HAS_RICH and (force_rich if force_rich is not None else _is_interactive())
    v_upper = str(verdict).upper()

    color_map = {
        "GREEN": "bold green",
        "YELLOW": "bold yellow",
        "RED": "bold red",
        "NEEDS_USER_INPUT": "bold magenta",
    }
    border_color = color_map.get(v_upper, "bold cyan")

    if use_rich and Panel and Console and box:
        body = f"[bold]Verdict:[/] [{border_color}]{verdict}[/{border_color}]\n[bold]Reason:[/]  {reason}"
        if install_method:
            body += f"\n[bold]Install Method:[/] {install_method}"

        panel = Panel(
            body,
            title=f"[{border_color}] ApkRevive Verdict: {verdict} [/{border_color}]",
            border_style=border_color,
            box=box.ROUNDED,
            padding=(0, 2),
            expand=False,
        )
        buf = io.StringIO()
        c = Console(file=buf, force_terminal=True, width=76)
        c.print(panel)
        return buf.getvalue().rstrip("\n")

    # Plain text fallback
    width = 72
    lines = [
        "=" * width,
        f"VERDICT: {verdict}",
        f"Reason:  {reason}",
    ]
    if install_method:
        lines.append(f"Install Method: {install_method}")
    lines.append("=" * width)
    return "\n".join(lines)


def render_triage_table(
    report_or_dict: Union[Dict[str, Any], Any],
    force_rich: Optional[bool] = None,
) -> str:
    """
    Renders diagnostic summary tables with risk levels and details.
    Accepts either a triage result dict, PatchReport dataclass, or general dict.
    """
    if hasattr(report_or_dict, "to_dict"):
        d = report_or_dict.to_dict()
    elif isinstance(report_or_dict, dict):
        d = report_or_dict
    else:
        d = vars(report_or_dict)

    verdict = str(d.get("verdict", "UNKNOWN"))
    reason = str(d.get("reason", "N/A"))
    install_method = d.get("install_method")
    transforms = d.get("required_transforms", []) or []
    transform_risks = d.get("transform_risks", {}) or {}
    warnings = d.get("warnings", []) or []
    details = str(d.get("details", "") or "")
    package_name = d.get("package_name")
    target_sdk = d.get("target_sdk")
    output_apk = d.get("output_apk")

    use_rich = HAS_RICH and (force_rich if force_rich is not None else _is_interactive())

    if use_rich and Table and Console and box:
        buf = io.StringIO()
        c = Console(file=buf, force_terminal=True, width=80)

        # Overview Table
        t_meta = Table(title="ApkRevive Diagnostic Summary", box=box.ROUNDED, expand=True)
        t_meta.add_column("Property", style="bold cyan", width=22)
        t_meta.add_column("Value")

        if package_name:
            t_meta.add_row("Package", str(package_name))
        if target_sdk is not None:
            t_meta.add_row("Target SDK", str(target_sdk))
        t_meta.add_row("Verdict", verdict)
        t_meta.add_row("Reason", reason)
        if install_method:
            t_meta.add_row("Install Method", str(install_method))
        if output_apk:
            t_meta.add_row("Output APK", str(output_apk))
        if details:
            t_meta.add_row("Details", details)

        c.print(t_meta)

        # Transforms Table
        if transforms:
            t_trans = Table(title="Required Transformations", box=box.ROUNDED, expand=True)
            t_trans.add_column("Transform", style="bold yellow")
            t_trans.add_column("Risk Level", width=15)
            for t in transforms:
                risk = transform_risks.get(t, "MEDIUM")
                risk_style = (
                    "bold red"
                    if risk in ("CRITICAL", "HIGH")
                    else ("bold yellow" if risk == "MEDIUM" else "bold green")
                )
                t_trans.add_row(t, f"[{risk_style}]{risk}[/{risk_style}]")
            c.print(t_trans)

        # Warnings Table
        if warnings:
            t_warn = Table(title="Diagnostic Warnings", box=box.ROUNDED, expand=True)
            t_warn.add_column("Code", style="bold yellow", width=26)
            t_warn.add_column("Remediation / Context")
            for w in warnings:
                if ":" in w:
                    code, rest = w.split(":", 1)
                    t_warn.add_row(code.strip(), rest.strip())
                else:
                    t_warn.add_row("WARNING", str(w))
            c.print(t_warn)

        return buf.getvalue().rstrip("\n")

    # Plain text fallback
    lines = [
        "ApkRevive Diagnostic Summary",
        "============================",
        f"Verdict: {verdict}",
        f"Reason: {reason}",
    ]
    if install_method:
        lines.append(f"Install Method: {install_method}")
    if package_name:
        lines.append(f"Package: {package_name}")
    if target_sdk is not None:
        lines.append(f"Target SDK: {target_sdk}")
    if output_apk:
        lines.append(f"Output APK: {output_apk}")

    if transforms:
        lines.append(f"Required Transforms ({len(transforms)}):")
        for t in transforms:
            risk = transform_risks.get(t, "MEDIUM")
            lines.append(f"  - {t} [Risk: {risk}]")
    else:
        lines.append("Required Transforms: None")

    if warnings:
        lines.append(f"Warnings ({len(warnings)}):")
        for w in warnings:
            lines.append(f"  - {w}")
    else:
        lines.append("Warnings: None")

    if details:
        lines.append(f"Details: {details}")

    return "\n".join(lines)


def render_alignment_ladder(
    ladder_entries: List[Dict[str, Any]],
    force_rich: Optional[bool] = None,
) -> str:
    """
    Renders an ASCII/Rich byte-alignment ladder for PT_LOAD and ZIP offsets.
    Accepts both single-state entries and before/after diff entries.
    """
    if not ladder_entries:
        return "No byte-alignment ladder entries recorded."

    use_rich = HAS_RICH and (force_rich if force_rich is not None else _is_interactive())

    is_diff = any("before" in e or "after" in e for e in ladder_entries)

    rows = []
    for item in ladder_entries:
        entry_name = item.get("entry") or item.get("name") or "unknown"
        entry_type = item.get("type", "ZIP")
        req_align = item.get("required_align", 4096)
        req_str = f"{req_align // 1024} KB" if req_align >= 1024 else f"{req_align} B"

        if is_diff:
            before = item.get("before") or {}
            after = item.get("after") or {}
            status = item.get("status")

            if "offset" in before:
                b_str = f"0x{before['offset']:08X}"
            elif "p_align" in before and before["p_align"] is not None:
                bv = before["p_align"]
                b_str = f"{bv // 1024}KB (0x{bv:X})" if bv >= 1024 else f"0x{bv:X}"
            else:
                b_str = "N/A"

            if "offset" in after:
                a_str = f"0x{after['offset']:08X}"
            elif "p_align" in after and after["p_align"] is not None:
                av = after["p_align"]
                a_str = f"{av // 1024}KB (0x{av:X})" if av >= 1024 else f"0x{av:X}"
            else:
                a_str = "N/A"

            if not status:
                status = "PASS" if after.get("aligned") else "FAIL"

            rows.append({
                "entry": entry_name,
                "type": entry_type,
                "required": req_str,
                "before": b_str,
                "after": a_str,
                "status": status,
            })
        else:
            offset = item.get("offset")
            aligned = item.get("aligned", False)
            off_str = f"0x{offset:08X}" if offset is not None else "N/A"
            status = item.get("status") or ("PASS" if aligned else "FAIL")
            rows.append({
                "entry": entry_name,
                "type": entry_type,
                "required": req_str,
                "offset": off_str,
                "status": status,
            })

    # ASCII Ladder Diagram
    ladder_lines = [
        "Byte-Alignment Ladder Diagram:",
        "  Offset     | Boundary Alignment Status",
        "  -----------+-------------------------------------------------------------",
    ]
    for r in rows:
        target = r["entry"]
        st = r["status"]
        marker = "|==" if st in ("PASS", "FIXED") else "|--"
        pos = r.get("after") if is_diff else r.get("offset")
        ladder_lines.append(f"  {pos:<10} {marker} [{r['required']}] {target} [{st}]")
    ladder_diagram = "\n".join(ladder_lines)

    if use_rich and Table and Console and box:
        buf = io.StringIO()
        c = Console(file=buf, force_terminal=True, width=84)

        t = Table(title="Byte Alignment Ladder", box=box.ROUNDED, expand=True)
        t.add_column("Target Entry", style="bold")
        t.add_column("Type", width=9)
        t.add_column("Required", width=10)
        if is_diff:
            t.add_column("Original", width=14)
            t.add_column("Revived", width=14)
        else:
            t.add_column("Offset", width=14)
        t.add_column("Status", width=10)

        for r in rows:
            st = r["status"]
            if st in ("PASS", "FIXED"):
                st_styled = f"[bold green]{st}[/bold green]"
            elif st in ("FAIL", "MISALIGNED"):
                st_styled = f"[bold red]{st}[/bold red]"
            else:
                st_styled = f"[bold yellow]{st}[/bold yellow]"

            if is_diff:
                t.add_row(r["entry"], r["type"], r["required"], r["before"], r["after"], st_styled)
            else:
                t.add_row(r["entry"], r["type"], r["required"], r["offset"], st_styled)

        c.print(t)
        c.print(ladder_diagram)
        return buf.getvalue().rstrip("\n")

    # Plain text table
    if is_diff:
        header = f"{'Target Entry':<36} {'Type':<8} {'Required':<10} {'Original':<14} {'Revived':<14} {'Status':<8}"
        sep = "-" * len(header)
        text_lines = [sep, header, sep]
        for r in rows:
            text_lines.append(
                f"{r['entry']:<36} {r['type']:<8} {r['required']:<10} {r['before']:<14} {r['after']:<14} {r['status']:<8}"
            )
        text_lines.append(sep)
    else:
        header = f"{'Target Entry':<36} {'Type':<8} {'Required':<10} {'Offset':<14} {'Status':<8}"
        sep = "-" * len(header)
        text_lines = [sep, header, sep]
        for r in rows:
            text_lines.append(
                f"{r['entry']:<36} {r['type']:<8} {r['required']:<10} {r['offset']:<14} {r['status']:<8}"
            )
        text_lines.append(sep)

    text_lines.append(ladder_diagram)
    return "\n".join(text_lines)