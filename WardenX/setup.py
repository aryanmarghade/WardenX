from setuptools import setup

setup(
    name="wardenx",
    version="1.0.0",
    description="A lightweight, cross-platform Endpoint Detection and Response (EDR) agent.",
    author="WardenX",
    py_modules=["cli", "database", "analyzer", "watcher", "enforcer", "service_manager", "scanner", "gui_app", "config", "heuristics", "network_shield", "canary_manager", "tray_app"],
    install_requires=[
        "click",
        "watchdog",
        "yara-python",
        "rich",
        "plyer"
    ],
    entry_points={
        "console_scripts": [
            "wardenx = cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
