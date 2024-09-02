# Project Name: Network MultiTool (NMT)

This repository contains a utility tool for managing IP-related tasks. The instructions provided below are specifically for macOS. 

## Table of Contents
- [Creating the .dmg File (macOS only)](#creating-the-dmg-file-macos-only)
- [Activating the Virtual Environment](#activating-the-virtual-environment)

## Creating the .dmg File (macOS only)

To create a `.dmg` (Disk Image) file for macOS using `pyinstaller`, follow these steps:

1. **Ensure you have PyInstaller installed:**
   ```bash
   pip install pyinstaller

2. **Use the following command to generate a standalone .dmg file:**
    ```bash
    pyinstaller --onefile --windowed --icon=/path/to/your/icon/icon.jpg your_script_name.py

    Replace the following in the command:
	•	/path/to/your/icon/icon.jpg with the path to your custom icon.
	•	your_script_name.py with the name of your Python script.
    
    This command will create a single executable file wrapped in a .dmg, making it easy to distribute your application on macOS.

## Activating the Virtual Environment

Before running any scripts or creating the .dmg file, make sure to activate your Python virtual environment:

1.	**Navigate to your project directory:**
    ```bash
    cd /path/to/your/project

2. **Activate the virtual environment:**
    ```bash
    source venv/bin/activate

This command activates the virtual environment named venv, isolating your project’s dependencies from the global Python environment.