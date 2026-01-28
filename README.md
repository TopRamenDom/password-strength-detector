# Password Strength Detector (Python)

Local-only password strength analyzer that scores passwords using:
- Length and character variety
- Entropy estimates
- Weak pattern detection (sequences, repeats, keyboard patterns)
- Common password detection

## Install
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -e .
