# Fighting the Cachers

An AES implementation game for ECE 576. Players design their own AES implementation by choosing between S-boxes, T-tables, Boolean masking, and specialized hardware. They then see how those choices affect encryption speed and resistance to a simulated cache timing attack.

## Requirements

- **Python 3.9 or newer.** Check your version with `python --version` (on macOS/Linux, use `python3`).
- **tkinter**, which draws the game window. It comes with the standard Python installers for Windows and macOS. On Linux, install it with your package manager, for example `sudo apt install python3-tk`.
- The Python packages listed in [`requirements.txt`](requirements.txt). Right now that is just `pycryptodome`, which performs the AES encryption.

## Setup

Open a terminal in the project folder (the one that contains `main.py`).

### 1. (Optional, recommended) Create a virtual environment

A virtual environment keeps this project's packages separate from the rest of your system.

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

When it's active, your prompt starts with `(.venv)`. Run the activate command again each time you open a new terminal.

### 2. Install the requirements

```bash
python -m pip install -r requirements.txt
```

The `-r` flag tells pip to install every package listed in `requirements.txt`. If you add a new package to the project, add it to that file so others can install it the same way.

## Running the game

From the project folder, with the virtual environment active if you created one:

```bash
python main.py
```

(Use `python3 main.py` on macOS/Linux if `python` isn't found.)

Keep the `assets` folder next to `main.py`. The intro slides load their images from it.

### Troubleshooting

- **`ModuleNotFoundError: No module named 'Crypto'`**: the requirements aren't installed in the Python you're using. Activate your virtual environment, or run step 2 again.
- **`ModuleNotFoundError: No module named 'tkinter'`**: install tkinter for your system (see [Requirements](#requirements)).
- **Do not install the package named `crypto` or `pycrypto`.** They conflict with `pycryptodome`. If you installed one by mistake, run `python -m pip uninstall crypto pycrypto` and then reinstall the requirements.

## Building a standalone executable (optional)

To share the game with people who don't have Python, you can bundle it into a single executable with [PyInstaller](https://pyinstaller.org/). PyInstaller is only needed for building, so it isn't in `requirements.txt`.

```bash
python -m pip install pyinstaller
```

```bash
python -m PyInstaller main.spec
```

This creates `dist/main.exe` on Windows, or `dist/main` on macOS/Linux, with the images already bundled inside. The `build/` and `dist/` folders are ignored by git, so build the executable locally rather than committing it. Executables only run on the operating system they were built on.
