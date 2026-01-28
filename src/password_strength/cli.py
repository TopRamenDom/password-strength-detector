# -------------------------
# Step 4: Simple CLI runner
# -------------------------

from password_strength.checker import score_password

def main() -> None:
    print("Password Strength Detector (local only — does not store passwords)")
    pw = input("Enter a password to test: ")

    result = score_password(pw)

    print("\n--- Result ---")
    print(f"Score: {result.score}/100")
    print(f"Label: {result.label}")
    print(f"Estimated entropy: {result.entropy_bits:.2f} bits")

    if result.feedback:
        print("\nSuggestions:")
        for tip in result.feedback:
            print(f"- {tip}")

if __name__ == "__main__":
    main()
