import pystray
from PIL import Image, ImageDraw
import subprocess
import sys
from pathlib import Path
import os
import threading
import config

def create_image(width, height):
    # Generate an image with a green circle and white border
    image = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    dc = ImageDraw.Draw(image)
    
    # White border
    dc.ellipse((0, 0, width, height), fill='white')
    # Green inner circle
    dc.ellipse((4, 4, width-4, height-4), fill='#4CAF50')
    
    return image

def on_start(icon, item):
    cli_path = Path(__file__).parent / "cli.py"
    subprocess.Popen([sys.executable, str(cli_path), "on"])

def on_stop(icon, item):
    cli_path = Path(__file__).parent / "cli.py"
    subprocess.Popen([sys.executable, str(cli_path), "off"])

def on_logs(icon, item):
    cli_path = Path(__file__).parent / "cli.py"
    if os.name == 'nt':
        subprocess.Popen(['cmd.exe', '/c', 'start', 'cmd.exe', '/k', f'"{sys.executable}" "{cli_path}" history scans'])
    else:
        # Fallback to run command, terminal might vary on Linux
        terminals = ['x-terminal-emulator', 'gnome-terminal', 'konsole', 'xfce4-terminal', 'xterm']
        for term in terminals:
            try:
                subprocess.Popen([term, '-e', f'{sys.executable} {cli_path} history scans'])
                break
            except FileNotFoundError:
                continue

def on_exit(icon, item):
    on_stop(icon, item)
    icon.stop()

def toggle_state(module_name):
    def toggle(icon, item):
        config.set_state(module_name, not config.get_state(module_name))
    return toggle

def check_state(module_name):
    def state(item):
        return config.get_state(module_name)
    return state

def snooze_protection(minutes):
    def _snooze(icon, item):
        config.set_all_states(False)
        def restore():
            config.set_all_states(True)
        threading.Timer(minutes * 60.0, restore).start()
    return _snooze

def setup_tray():
    image = create_image(64, 64)
    
    protection_menu = pystray.Menu(
        pystray.MenuItem('File Watcher', toggle_state('FILE_WATCHER_ACTIVE'), checked=check_state('FILE_WATCHER_ACTIVE')),
        pystray.MenuItem('Network Shield', toggle_state('NETWORK_SHIELD_ACTIVE'), checked=check_state('NETWORK_SHIELD_ACTIVE')),
        pystray.MenuItem('Canary Honeypot', toggle_state('CANARY_ACTIVE'), checked=check_state('CANARY_ACTIVE'))
    )
    
    snooze_menu = pystray.Menu(
        pystray.MenuItem('5 Minutes', snooze_protection(5)),
        pystray.MenuItem('15 Minutes', snooze_protection(15)),
        pystray.MenuItem('30 Minutes', snooze_protection(30))
    )

    menu = pystray.Menu(
        pystray.MenuItem('Status: Active', None, enabled=False),
        pystray.MenuItem('Start WardenX', on_start),
        pystray.MenuItem('Stop WardenX', on_stop),
        pystray.MenuItem('Protection Modules', protection_menu),
        pystray.MenuItem('Pause Protection', snooze_menu),
        pystray.MenuItem('View Logs', on_logs),
        pystray.MenuItem('Exit', on_exit)
    )
    
    icon = pystray.Icon("WardenX", image, "WardenX EDR", menu)
    
    # Start WardenX on boot
    on_start(None, None)
    
    icon.run()

if __name__ == "__main__":
    setup_tray()
