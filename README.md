# Password Strength Detector (Python)

Local-only password strength analyzer that scores passwords using:
- Length and character variety
- Entropy estimates
- Weak pattern detection (sequences, repeats, keyboard patterns)
- Common password detection

## Install (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pw-strength

