Ransomware-Detection-Tool

A simple Python tool to monitor file changes and detect ransomware-like behavior by tracking unusual activities in a specified folder.

Overview

This project is designed to help users monitor their file system for unusual activity that may indicate a ransomware attack. The tool logs events such as file creation, modification, and deletion, and provides alerts in real time.

Features

- Monitors a specified folder for file activity.
- Detects file creation, modification, and deletion.
- Logs events to a file ('ransomware_detection.log').
- Prints alerts to the console for real-time monitoring.

Requirements

- Python 3.x
- "watchdog" library
