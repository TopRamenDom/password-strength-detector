import math
import re 
from dataclasses import dataclass 
from typing import List, Tuple
# -------------------------
# Step 1: Data structures
# -------------------------

@dataclass
class StrengthResult:
    score: int
    label: str
    entropy_bits: float
    feedback: List[str]

# -------------------------
# Step 2: Helper checks
# -------------------------



COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein", "admin", "password1", "welcome", "iloveyou", "monkey", "dragon", "football"

}

KEYBOARD_PATTERNS = [
    "qwerty","asdf","zxcv","poiuy","lkjh","mnbv","12345","67890"

]

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789"
]


def detect_charsets(pw: str) -> Tuple[int, List[str]]:
    """
    This helps us approximate entropy and also give useful feedback.

    """
    sets_size = 0 
    
    used = []

    if re.search(r"[a-z]", pw):
        sets_size += 26
        used.append("lowercase")
    if re.search(r"[A-Z]", pw):
        sets_size += 26
        used.append("uppercase")
    if re.search(r"[0-9]", pw):
        sets_size += 10
        used.append("digits")
    if re.search(r"[^a-zA-Z0-9]", pw):
        sets_size += 33
        used.append("symbols")
    return sets_size, used


def shannon_entropy_bits(pw: str) -> float:
    """
    Shannon entropy estimates unpredictability based on character frequency.
    Not perfect for passwords (patterns can still be predictable), but useful.
    """


    if not pw:
        return 0.0 
    

    freq = {}
    for ch in pw:
        freq[ch] = freq.get(ch, 0) + 1
    

    length = len(pw)
    entropy = 0.0 
    for count in freq.values():
        p = count / length 
        entropy -= p * math.log2(p)


    return entropy * length


def estimated_search_space_entropy_bits(pw: str) -> float:
    """
    This assumes random selection from detected charsets.
    """


    charset_size, _ = detect_charsets(pw)
    if charset_size == 0:
        return 0.0 
    return len(pw) * math.log2(charset_size)



def has_repeated_runs(pw: str, run_len: int = 4) -> bool:
    """
    Detect runs like 'aaaa' or '1111'. Repetition reduces effective complexity.
    """

    pattern = r"(.)\1{" + str(run_len - 1) + r",}"
    return re.search(pattern, pw) is not None




def has_sequence(pw: str, seq_len: int = 4) -> bool:
    """
    Detect simple sequences like 'abcd', '9876', etc.
    Attackers try these early.
    """
    lower = pw.lower()

    for seq in SEQUENCES:
        seq_lower = seq.lower()

        for i in range(len(seq_lower) - seq_len + 1):
            chunk = seq_lower[i:i+seq_len]
            if chunk in lower:
                return True
    
        rev = seq_lower[::-1]
        for i in range(len(rev)- seq_len + 1):
            chunk = rev[i:i+seq_len]
            if chunk in lower:
                return True
            

    return False


def has_keyboard_pattern(pw: str, min_len: int = 4) -> bool:
     """
    Detect very common keyboard patterns like 'qwerty' or 'asdf'.
    """
     lower = pw.lower()
     return any(pat for pat in KEYBOARD_PATTERNS if len(pat) >= min_len and pat in lower)


def looks_like_common_password(pw: str) -> bool:
    """
    Catch exact matches and trivial variations (case changes, trailing digits).
    """
    raw = pw.strip()
    lower = raw.lower()

    if lower in COMMON_PASSWORDS:

        return True
    

    # password + digits (e.g, password123)
    
    if re.match(r"^[a-zA-Z]+[0-9]{1,4}$", raw):
        base = re.sub(r"[0-9]+$", "", raw).lower()
        if base in  COMMON_PASSWORDS: 

            return True
        
    # simple leetspeak normilization for a few common substitutions

    leet_map = str.maketrans({"@": "a", "0": "o", "1": "i", "!": "i", "$": "s", "3": "e"})
    normalized = lower.translate(leet_map)
    if normalized in COMMON_PASSWORDS:
        return True


    return False



def score_password(pw: str) -> StrengthResult:
    
    feedback: List[str] = []


    if not pw: 
        return StrengthResult(score=0, label="Very Weak", entropy_bits=0.0,
                              feedback=["Password is empty"])
    
    length = len(pw)

    # 1) Entropy estimates (two different ways)

    shannon_bits = shannon_entropy_bits(pw)
    space_bits = estimated_search_space_entropy_bits(pw)

    # we'll use a conservative entropy number (min of the two)
    entropy_bits = min(shannon_bits, space_bits)

    #2) start scoring

    score = 0

    # length scoring (max 40 points)

    if length < 8:
        score += 5 
        feedback.append("Too short: aim for at least 12-16 characters.")
    elif length < 12:
        score += 20
        feedback.append("Decent length, but 12-16+ is better.")
    elif length < 16: 
        score += 32 
    else:
        score += 40

    # 3) charset variety (max 20 points)
    
    charset_size, used_sets = detect_charsets(pw)
    score += min(20, len(used_sets) * 5)

    if "lowercase" not in used_sets:
        feedback.append("add lowercase letters to increase variety.")
    if "uppercase" not in used_sets:
        feedback.append("Add uppercase letters to increase variety.")
    if "digits" not in used_sets:
        feedback.append("Add digits to increase variety.")
    if "symbols" not in used_sets:
        feedback.append("Add symbols(e.g., !@#$) to increase variety.")
    
    # 4) Entropy contribution (max 25 points)
    # Rough mapping: 0-80 bits to 0-25 points

    score += int(min(25, (entropy_bits  / 80.0) * 25))


    # 5) Penalize known-bad patterns (up to -35)

    penalties = 0

    if looks_like_common_password(pw):
        penalties += 25
        feedback.append("This looks like a common password or easy variation-avoid it.")
    
    if has_repeated_runs(pw):
        penalties += 8 
        feedback.append("Avoid repeated characters (e.g., aaaa, 1111).")
    
    if has_keyboard_pattern(pw):
        penalties += 6
        feedback.append("Avoid keyboard patterns (e.g., qwerty, asdf).")

    score -= penalties 

    # clamp score to 0-100
    score = max(0, min(100, score))

    # 6) Label
    if score < 20:
        label = "Very Weak"
    if score < 40:
        label = "Weak"
    if score < 60:
        label = "fair"
    if score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    # 7) Clean up feedback
    if not feedback and score >= 80:
        feedback.append("Great password. Consider using a password manager to generate/store unique passwords.")


    return StrengthResult(score=score, label=label, entropy_bits=entropy_bits, feedback=feedback)


# -------------------------
# Step 4: Simple CLI runner
# -------------------------

def main() -> None:
    print("Password Strength Detector (local only - does not store passwords)")
    pw = input("Enter a password to test: ")

    result = score_password(pw)

    print("\n--- Result ---")
    print(f"Score: {result.score}/100")
    print(f"Label: {result.label}")
    print(f"Estimated entropy: {result.entropy_bits:.2f} bits")

    if result.feedback:
        print("\nsuggestions:")
        for tip in result.feedback:
            print(f"- {tip}")


if __name__ == "__main__":
    main()

        
