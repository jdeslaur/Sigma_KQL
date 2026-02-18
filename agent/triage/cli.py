"""
Human-in-the-loop triage CLI.

Displays pending hits in a rich terminal table and lets an analyst
approve, reject, or snooze each one before rehydration is triggered.

Dependencies:
    pip install rich

Usage:
    from agent.triage.cli import TriageCLI
    cli = TriageCLI(hit_store)
    cli.run()
"""

import json
import logging
import textwrap
from typing import Callable, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .state import HitRecord, HitStatus, HitStore

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLOUR = {
    "critical":    "bold red",
    "high":        "red",
    "medium":      "yellow",
    "low":         "cyan",
    "informational": "dim",
}

_STATUS_COLOUR = {
    HitStatus.PENDING:    "yellow",
    HitStatus.APPROVED:   "green",
    HitStatus.REJECTED:   "red",
    HitStatus.SNOOZED:    "dim",
    HitStatus.REHYDRATED: "blue",
    HitStatus.FORWARDED:  "magenta",
}


def _status_text(status: HitStatus) -> Text:
    colour = _STATUS_COLOUR.get(status, "white")
    return Text(status.value.upper(), style=colour)


# ---------------------------------------------------------------------------
# Triage CLI
# ---------------------------------------------------------------------------

class TriageCLI:
    """
    Interactive terminal UI for reviewing threat hunt hits.

    Args:
        hit_store:            HitStore instance
        on_approve:           Callback(hit_id) called when analyst approves a hit
        on_reject:            Callback(hit_id, note) called on rejection
    """

    def __init__(
        self,
        hit_store: HitStore,
        on_approve: Optional[Callable[[str], None]] = None,
        on_reject: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._store = hit_store
        self._on_approve = on_approve
        self._on_reject = on_reject

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Interactive triage session — loops until the analyst exits."""
        console.print(Panel.fit(
            "[bold cyan]Threat Hunt Triage Console[/bold cyan]\n"
            "[dim]Review Cribl Search hits and approve/reject rehydration[/dim]",
            border_style="cyan",
        ))

        while True:
            pending = self._store.get_pending()
            if not pending:
                console.print("\n[green]No pending hits. All clear.[/green]")
                break

            self._show_summary()
            self._show_hit_table(pending)

            choice = Prompt.ask(
                "\nEnter hit # to review, [bold]a[/bold]ll approve, [bold]q[/bold]uit",
                default="q",
            ).strip().lower()

            if choice == "q":
                break
            elif choice == "a":
                self._approve_all(pending)
            else:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(pending):
                        self._review_hit(pending[idx])
                    else:
                        console.print("[red]Invalid number.[/red]")
                except ValueError:
                    console.print("[red]Please enter a number, 'a', or 'q'.[/red]")

        console.print("\n[dim]Triage session ended.[/dim]")

    # ------------------------------------------------------------------
    # Summary panel
    # ------------------------------------------------------------------

    def _show_summary(self) -> None:
        counts = self._store.count_by_status()
        parts = [f"[bold]{s}[/bold]: {c}" for s, c in sorted(counts.items())]
        console.print("\n" + " | ".join(parts))

    # ------------------------------------------------------------------
    # Hit list table
    # ------------------------------------------------------------------

    def _show_hit_table(self, hits: list[HitRecord]) -> None:
        table = Table(
            title="Pending Hits",
            box=box.ROUNDED,
            show_lines=False,
            highlight=True,
        )
        table.add_column("#", style="dim", width=4, no_wrap=True)
        table.add_column("IOC Type", width=12)
        table.add_column("IOC Value", width=28)
        table.add_column("Events", justify="right", width=8)
        table.add_column("Description", width=40)
        table.add_column("DET Strategies", width=20)
        table.add_column("Status", width=10)

        for i, hit in enumerate(hits, start=1):
            ioc_val = hit.ioc_value
            if len(ioc_val) > 26:
                ioc_val = ioc_val[:24] + "…"

            desc = hit.description
            if len(desc) > 38:
                desc = desc[:36] + "…"

            det_strats = ", ".join(hit.det_strategies[:3]) or "—"

            table.add_row(
                str(i),
                hit.ioc_type,
                ioc_val,
                str(hit.event_count),
                desc,
                det_strats,
                _status_text(hit.status),
            )

        console.print(table)

    # ------------------------------------------------------------------
    # Single hit review
    # ------------------------------------------------------------------

    def _review_hit(self, hit: HitRecord) -> None:
        console.print()
        console.print(Panel(
            self._hit_detail(hit),
            title=f"[bold]Hit: {hit.hit_id[:12]}…[/bold]",
            border_style="yellow",
        ))

        action = Prompt.ask(
            "[A]pprove rehydration  [R]eject  [S]nooze  [N]ote only  [C]ancel",
            choices=["a", "r", "s", "n", "c"],
            default="c",
        ).lower()

        if action == "c":
            return

        note = ""
        if action in ("a", "r", "n"):
            note = Prompt.ask("Analyst note (optional)", default="")

        if action == "a":
            self._store.update_status(hit.hit_id, HitStatus.APPROVED, note=note)
            console.print("[green]✓ Hit approved for rehydration.[/green]")
            if self._on_approve:
                self._on_approve(hit.hit_id)

        elif action == "r":
            self._store.update_status(hit.hit_id, HitStatus.REJECTED, note=note)
            console.print("[red]✗ Hit rejected.[/red]")
            if self._on_reject:
                self._on_reject(hit.hit_id, note)

        elif action == "s":
            self._store.update_status(hit.hit_id, HitStatus.SNOOZED, note="Snoozed by analyst")
            console.print("[dim]Hit snoozed.[/dim]")

        elif action == "n":
            if note:
                self._store.update_status(hit.hit_id, hit.status, note=note)
                console.print("[dim]Note saved.[/dim]")

    def _hit_detail(self, hit: HitRecord) -> str:
        lines = [
            f"[bold]IOC Type:[/bold]     {hit.ioc_type}",
            f"[bold]IOC Value:[/bold]    {hit.ioc_value}",
            f"[bold]Event Count:[/bold]  {hit.event_count}",
            f"[bold]Description:[/bold]  {hit.description}",
            f"[bold]Cribl Job:[/bold]    {hit.cribl_job_id}",
            "",
            f"[bold]Sigma Rules:[/bold]  {', '.join(hit.matched_rules) or '—'}",
            f"[bold]DET Strategies:[/bold] {', '.join(hit.det_strategies) or '—'}",
            "",
            "[bold]Query:[/bold]",
            f"[dim]{textwrap.fill(hit.query, width=80)}[/dim]",
        ]

        if hit.sample_events:
            lines += ["", "[bold]Sample events:[/bold]"]
            for i, ev in enumerate(hit.sample_events[:3], 1):
                raw = ev.get("_raw") or json.dumps(ev)[:200]
                lines.append(f"  [{i}] {raw[:200]}")

        if hit.analyst_note:
            lines += ["", f"[bold]Analyst note:[/bold] {hit.analyst_note}"]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Bulk approve
    # ------------------------------------------------------------------

    def _approve_all(self, hits: list[HitRecord]) -> None:
        note = Prompt.ask(f"Approve all {len(hits)} pending hits? Add note (or press Enter)", default="")
        confirmed = Prompt.ask("Confirm? [y/N]", default="n").lower()
        if confirmed != "y":
            console.print("[dim]Cancelled.[/dim]")
            return

        for hit in hits:
            self._store.update_status(hit.hit_id, HitStatus.APPROVED, note=note)
            if self._on_approve:
                self._on_approve(hit.hit_id)

        console.print(f"[green]✓ {len(hits)} hits approved.[/green]")


# ---------------------------------------------------------------------------
# Non-interactive mode: print a summary and exit
# ---------------------------------------------------------------------------

def print_summary(hit_store: HitStore) -> None:
    """Print a one-shot status summary (useful for cron/CI output)."""
    counts = hit_store.count_by_status()
    console.print("[bold]Threat Hunt Summary[/bold]")
    for status, count in sorted(counts.items()):
        colour = _STATUS_COLOUR.get(HitStatus(status), "white")
        console.print(f"  [{colour}]{status:12s}[/{colour}]  {count}")
    pending = hit_store.get_pending()
    if pending:
        console.print(f"\n[yellow]{len(pending)} hit(s) awaiting analyst review.[/yellow]")
