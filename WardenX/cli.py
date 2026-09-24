import click
import os
import sys
import subprocess
import logging
import time
from datetime import datetime
from pathlib import Path
from database import get_recent_scans, get_recent_blocks, get_stats, clear_db
from service_manager import install_service

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box

console = Console()

logging.basicConfig(level=logging.INFO, format='%(message)s')

def get_pid_file():
    return Path.home() / ".wardenx_pid"

def is_running():
    pid_file = get_pid_file()
    if pid_file.exists():
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            
            if os.name == 'nt':
                import ctypes
                kernel32 = ctypes.windll.kernel32
                process = kernel32.OpenProcess(0x100000, 0, pid)
                if process != 0:
                    kernel32.CloseHandle(process)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except (ProcessLookupError, ValueError, OSError):
            return False
    return False

@click.group()
def cli():
    """WardenX: A lightweight Endpoint Detection and Response (EDR) agent."""
    pass

@cli.command()
def on():
    """Starts the WardenX background daemon."""
    if is_running():
        console.print("[bold yellow]⚠ WardenX is already running.[/bold yellow]")
        return

    script_path = Path(__file__).parent / "watcher.py"
    
    log_path = Path.home() / ".wardenx_daemon.log"
    if os.name == 'nt':
        with open(log_path, "a") as f:
            process = subprocess.Popen([sys.executable, str(script_path)], 
                                       creationflags=0x00000008,
                                       stdout=f,
                                       stderr=f)
    else:
        with open(log_path, "a") as f:
            process = subprocess.Popen([sys.executable, str(script_path)],
                                       preexec_fn=os.setsid,
                                       stdout=f,
                                       stderr=f)
                                   
    with open(get_pid_file(), "w") as f:
        f.write(str(process.pid))
        
    console.print(f"[bold green]✔ WardenX started (PID: {process.pid}).[/bold green]")

@cli.command()
def off():
    """Stops the WardenX background daemon."""
    if not is_running():
        console.print("[bold yellow]⚠ WardenX is not running.[/bold yellow]")
        return
        
    pid_file = get_pid_file()
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
            
        if os.name == 'nt':
            subprocess.call(['taskkill', '/F', '/PID', str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            import signal
            os.kill(pid, signal.SIGTERM)
            
        pid_file.unlink(missing_ok=True)
        console.print("[bold red]⛔ WardenX stopped.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]✖ Error stopping WardenX: {e}[/bold red]")

@cli.command(name='install-service')
def install_service_cmd():
    """Installs WardenX as an OS startup service."""
    console.print("[bold cyan]Installing OS persistence service...[/bold cyan]")
    install_service()

@cli.group()
def history():
    """View WardenX history logs."""
    pass

def generate_scans_table(limit=15):
    scans_data = get_recent_scans(limit=limit)
    if not scans_data:
        return Panel("No records found", title="🔍 WardenX Scan History", border_style="yellow", expand=False)
        
    table = Table(title="🔍 WardenX Scan History", show_header=True, header_style="bold blue")
    table.add_column("Timestamp", style="dim")
    table.add_column("File Name")
    table.add_column("Hash", overflow="fold")
    table.add_column("Engine")
    table.add_column("Verdict", justify="center")
    
    for row in scans_data:
        try:
            dt = datetime.fromisoformat(row[0])
            timestamp = dt.strftime('%b %d, %Y %I:%M %p')
        except ValueError:
            timestamp = row[0]
            
        file_path, file_hash, engine, verdict = row[1], row[2], row[3], row[4]
        file_name = Path(file_path).name
        
        style = "green" if verdict.lower() == "benign" else "bold red"
        table.add_row(timestamp, file_name, file_hash, engine, verdict, style=style)
        
    return table

@history.command()
def scans():
    """Prints the latest 15 entries from scan_history."""
    console.print(generate_scans_table(15))

@history.command()
def blocks():
    """Prints the latest 15 entries from block_history."""
    blocks_data = get_recent_blocks(limit=15)
    if not blocks_data:
        console.print(Panel("No records found", title="⛔ WardenX Block History", border_style="yellow", expand=False))
        return
        
    table = Table(title="⛔ WardenX Block History", show_header=True, header_style="bold red", border_style="red", box=box.HEAVY)
    table.add_column("Timestamp", style="dim")
    table.add_column("Original File")
    table.add_column("Quarantine Path")
    table.add_column("Signature")
    
    for row in blocks_data:
        try:
            dt = datetime.fromisoformat(row[0])
            timestamp = dt.strftime('%b %d, %Y %I:%M %p')
        except ValueError:
            timestamp = row[0]
            
        original_path, quarantine_path, signature = row[1], row[2], row[3]
        table.add_row(timestamp, Path(original_path).name, quarantine_path, signature)
        
    console.print(table)

@cli.command()
def clear():
    """Clears all WardenX logs and scan history."""
    clear_db()
    
    # Also clear the background daemon plain-text log
    log_path = Path.home() / ".wardenx_daemon.log"
    if log_path.exists():
        with open(log_path, "w") as f:
            f.write("")
            
    console.print("[bold green]✔ All WardenX logs and history have been cleared![/bold green]")

@cli.command()
def stats():
    """Displays WardenX security statistics."""
    total_scans, total_blocks = get_stats()
    
    stats_text = (
        f"[bold cyan]Total Scans:[/bold cyan] {total_scans}\n"
        f"[bold red]Total Threats Blocked:[/bold red] {total_blocks}"
    )
    
    panel = Panel(
        stats_text,
        title="[bold green]🛡️ WardenX Security Status[/bold green]",
        expand=False,
        border_style="green"
    )
    
    console.print(panel, justify="center")

@cli.command()
@click.option('--follow', '-f', is_flag=True, help="Continuously output live scan logs.")
def logs(follow):
    """Live tail for WardenX scan logs."""
    if not follow:
        console.print(generate_scans_table(15))
        return
        
    with Live(generate_scans_table(15), refresh_per_second=1) as live:
        try:
            while True:
                time.sleep(1)
                live.update(generate_scans_table(15))
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    cli()
