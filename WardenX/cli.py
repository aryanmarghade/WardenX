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
from canary_manager import deploy_canaries, cleanup_canaries
import config

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
                pids_str = f.read().strip()
                if not pids_str:
                    return False
                pids = [int(p) for p in pids_str.split(',')]
            
            # Check if at least one is running
            any_running = False
            for pid in pids:
                if os.name == 'nt':
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    process = kernel32.OpenProcess(0x100000, 0, pid)
                    if process != 0:
                        kernel32.CloseHandle(process)
                        any_running = True
                        break
                else:
                    try:
                        os.kill(pid, 0)
                        any_running = True
                        break
                    except OSError:
                        pass
            return any_running
        except (ProcessLookupError, ValueError, OSError):
            return False
    return False

class RichGroup(click.Group):
    def format_help(self, ctx, formatter):
        help_text = (
            "[bold green]WardenX EDR - Cross-Platform Security Agent[/bold green]\n\n"
            "[bold cyan]Daemon Commands:[/bold cyan]\n"
            "  [yellow]on[/yellow]               Start the WardenX background daemon\n"
            "  [yellow]off[/yellow]              Stop the WardenX background daemon\n"
            "  [yellow]install-service[/yellow]  Install as OS startup service\n\n"
            "[bold cyan]Protection Controls:[/bold cyan]\n"
            "  [yellow]shield on[/yellow]        Enable specific protection modules (file, network, canary, all)\n"
            "  [yellow]shield off[/yellow]       Disable specific protection modules (file, network, canary, all)\n"
            "  [yellow]pause[/yellow]            Snooze all protections for a specified duration\n\n"
            "[bold cyan]Analytics & Logs:[/bold cyan]\n"
            "  [yellow]history[/yellow]          View scan and block logs\n"
            "  [yellow]logs[/yellow]             Live tail for WardenX scan logs\n"
            "  [yellow]stats[/yellow]            Displays WardenX security statistics\n"
            "  [yellow]clear[/yellow]            Clears all WardenX logs and scan history"
        )
        console.print(Panel(help_text, title="🛡️ WardenX Help", border_style="blue", box=box.ROUNDED))

@click.group(cls=RichGroup)
def cli():
    """WardenX: A lightweight Endpoint Detection and Response (EDR) agent."""
    pass

@cli.command()
def on():
    """Starts the WardenX background daemon."""
    if is_running():
        console.print("[bold yellow]⚠ WardenX is already running.[/bold yellow]")
        return
        
    deploy_canaries()

    script_path = Path(__file__).parent / "watcher.py"
    net_script_path = Path(__file__).parent / "network_shield.py"
    
    log_path = Path.home() / ".wardenx_daemon.log"
    if os.name == 'nt':
        with open(log_path, "a") as f:
            process = subprocess.Popen([sys.executable, str(script_path)], 
                                       creationflags=0x00000008,
                                       stdout=f,
                                       stderr=f)
            net_process = subprocess.Popen([sys.executable, str(net_script_path)], 
                                       creationflags=0x00000008,
                                       stdout=f,
                                       stderr=f)
    else:
        with open(log_path, "a") as f:
            process = subprocess.Popen([sys.executable, str(script_path)],
                                       preexec_fn=os.setsid,
                                       stdout=f,
                                       stderr=f)
            net_process = subprocess.Popen([sys.executable, str(net_script_path)],
                                       preexec_fn=os.setsid,
                                       stdout=f,
                                       stderr=f)
                                   
    with open(get_pid_file(), "w") as f:
        f.write(f"{process.pid},{net_process.pid}")
        
    console.print(f"[bold green]✔ WardenX started (PIDs: {process.pid}, {net_process.pid}).[/bold green]")

@cli.command()
def off():
    """Stops the WardenX background daemon."""
    if not is_running():
        console.print("[bold yellow]⚠ WardenX is not running.[/bold yellow]")
        return
        
    pid_file = get_pid_file()
    try:
        with open(pid_file, "r") as f:
            pids = f.read().strip().split(',')
            
        for pid_str in pids:
            pid = int(pid_str)
            if os.name == 'nt':
                subprocess.call(['taskkill', '/F', '/PID', str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                import signal
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            
        pid_file.unlink(missing_ok=True)
        cleanup_canaries()
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

@cli.group()
def shield():
    """Granular control of WardenX modules."""
    pass

@shield.command(name='on')
@click.argument('module', type=click.Choice(['file', 'network', 'canary', 'all']))
def shield_on(module):
    """Enable a protection module."""
    if module in ('all', 'file'):
        config.set_state('FILE_WATCHER_ACTIVE', True)
    if module in ('all', 'network'):
        config.set_state('NETWORK_SHIELD_ACTIVE', True)
    if module in ('all', 'canary'):
        config.set_state('CANARY_ACTIVE', True)
    console.print(f"[bold green]✔ Shield '{module}' enabled.[/bold green]")

@shield.command(name='off')
@click.argument('module', type=click.Choice(['file', 'network', 'canary', 'all']))
def shield_off(module):
    """Disable a protection module."""
    if module in ('all', 'file'):
        config.set_state('FILE_WATCHER_ACTIVE', False)
    if module in ('all', 'network'):
        config.set_state('NETWORK_SHIELD_ACTIVE', False)
    if module in ('all', 'canary'):
        config.set_state('CANARY_ACTIVE', False)
    console.print(f"[bold yellow]⚠ Shield '{module}' disabled.[/bold yellow]")

@cli.command()
@click.option('--duration', type=str, required=True, help="Duration to snooze (e.g., 15m)")
def pause(duration):
    """Snooze protections temporarily."""
    if duration.endswith('m'):
        minutes = int(duration[:-1])
    else:
        minutes = int(duration)
        
    config.set_all_states(False)
    console.print(f"[bold yellow]⚠ All protections paused for {minutes} minutes. Blocking terminal...[/bold yellow]")
    try:
        time.sleep(minutes * 60)
    except KeyboardInterrupt:
        pass
    finally:
        config.set_all_states(True)
        console.print(f"[bold green]✔ Protections restored.[/bold green]")

if __name__ == '__main__':
    cli()
