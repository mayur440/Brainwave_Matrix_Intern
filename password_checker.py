#!/usr/bin/env python3
import sys
import re
import json
import math
import argparse
from getpass import getpass

COMMON = {
    "123456","password","123456789","12345","12345678","qwerty","1234567","111111","123123","abc123","password1","iloveyou","admin","welcome","monkey","dragon","letmein","football","baseball","starwars","hello","freedom","whatever","qazwsx","trustno1","passw0rd","qwerty123","pokemon","princess","sunshine","charlie","donald","login","zaq1zaq2","1q2w3e4r","1qaz2wsx","qwertyuiop","asdfghjkl","p@ssw0rd","qwerty1","000000"
}

SEQ_KEYS = [
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnm",
    "0123456789"
]

SYMBOLS = r"!@#$%^&*()_+-={}[]:;\"'<>,.?/|\\`~"

class Result:
    def __init__(self, password: str):
        self.password = password
        self.score = 0
        self.rating = ""
        self.entropy_bits = 0.0
        self.crack_time = ""
        self.feedback = []
        self.factors = {}

    def to_dict(self):
        return {
            "score": self.score,
            "rating": self.rating,
            "entropy_bits": round(self.entropy_bits, 2),
            "crack_time": self.crack_time,
            "feedback": self.feedback,
            "factors": self.factors,
        }

def pool_size(pw: str) -> int:
    pools = 0
    pools += any(c.islower() for c in pw)
    pools += any(c.isupper() for c in pw)
    pools += any(c.isdigit() for c in pw)
    pools += any(c in SYMBOLS for c in pw)
    size = 0
    if any(c.islower() for c in pw):
        size += 26
    if any(c.isupper() for c in pw):
        size += 26
    if any(c.isdigit() for c in pw):
        size += 10
    if any(c in SYMBOLS for c in pw):
        size += len(SYMBOLS)
    return size or 1

def entropy_bits(pw: str) -> float:
    return len(pw) * math.log2(pool_size(pw))

def crack_time_from_entropy(bits: float) -> str:
    gps = 1e10
    seconds = (2 ** (bits - 1)) / gps
    intervals = [
        (60, "seconds"),
        (60, "minutes"),
        (24, "hours"),
        (365, "days"),
        (1000, "years")
    ]
    value = seconds
    unit = "seconds"
    for div, name in intervals:
        if value < div:
            break
        value /= div
        unit = name
    if value < 1:
        return "< 1 second"
    return f"~{value:.1f} {unit}"

def has_sequence(pw: str, min_len: int = 4) -> bool:
    s = pw.lower()
    for seq in SEQ_KEYS:
        for i in range(len(seq) - min_len + 1):
            sub = seq[i:i+min_len]
            if sub in s or sub[::-1] in s:
                return True
    return False

def repeated_patterns(pw: str) -> bool:
    return bool(re.search(r"(.{1,3})\1{2,}", pw))

def years_or_dates(pw: str) -> bool:
    if re.search(r"(19|20)\d{2}", pw):
        return True
    if re.search(r"\b\d{2}[\/-]\d{2}[\/-]\d{2,4}\b", pw):
        return True
    return False

def evaluate(password: str) -> Result:
    r = Result(password)
    pw = password
    length = len(pw)

    if length == 0:
        r.feedback.append("Empty password")
        r.rating = "very weak"
        r.factors["length"] = 0
        return r

    score = 0

    if length >= 8:
        score += 10
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10

    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in SYMBOLS for c in pw)
    ])
    score += (classes - 1) * 10

    if pw.lower() in COMMON:
        score -= 40
        r.feedback.append("Common password")

    if pw.isdigit():
        score -= 10
        r.feedback.append("Only digits")
    if pw.isalpha():
        score -= 5
        r.feedback.append("Only letters")

    if has_sequence(pw):
        score -= 10
        r.feedback.append("Contains keyboard/alphabetic sequence")

    if repeated_patterns(pw):
        score -= 10
        r.feedback.append("Contains repeated patterns")

    if years_or_dates(pw):
        score -= 10
        r.feedback.append("Contains year/date pattern")

    unique_chars = len(set(pw))
    score += min(max(unique_chars - 4, 0), 10)

    r.entropy_bits = entropy_bits(pw)

    if r.entropy_bits < 28:
        score -= 20
    elif r.entropy_bits < 36:
        score -= 10
    elif r.entropy_bits > 60:
        score += 10
    elif r.entropy_bits > 80:
        score += 15

    score = max(0, min(100, score))
    r.score = score

    if score < 20:
        r.rating = "very weak"
    elif score < 40:
        r.rating = "weak"
    elif score < 60:
        r.rating = "fair"
    elif score < 80:
        r.rating = "strong"
    else:
        r.rating = "very strong"

    r.factors["length"] = length
    r.factors["classes"] = classes
    r.factors["unique_chars"] = unique_chars

    suggestions = []
    if length < 12:
        suggestions.append("Use 12+ characters")
    if classes < 3:
        suggestions.append("Mix upper, lower, digits, and symbols")
    if unique_chars < max(6, length // 2):
        suggestions.append("Avoid repeating characters")
    if pw.lower() in COMMON:
        suggestions.append("Do not use common passwords")
    if has_sequence(pw):
        suggestions.append("Avoid sequences like 'abcd' or '1234'")
    if years_or_dates(pw):
        suggestions.append("Avoid years or dates")

    if not suggestions and score < 100:
        suggestions.append("Add a few more random characters")

    r.feedback.extend(suggestions)
    r.crack_time = crack_time_from_entropy(r.entropy_bits)
    return r

def main():
    p = argparse.ArgumentParser(description="Password Strength Checker")
    p.add_argument("password", nargs="?", help="Password to evaluate (omit to be prompted)")
    p.add_argument("-j", "--json", action="store_true", help="Output JSON")
    p.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    args = p.parse_args()

    if args.password is None:
        pw = getpass("Enter password: ")
        if not pw:
            print("No password provided", file=sys.stderr)
            sys.exit(1)
    else:
        pw = args.password

    res = evaluate(pw)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return

    if args.quiet:
        print(f"{res.rating} ({res.score}/100)")
        return

    print("Password Strength Report")
    print(f"Rating: {res.rating} ({res.score}/100)")
    print(f"Entropy: {res.entropy_bits:.2f} bits")
    print(f"Estimated crack time: {res.crack_time}")
    if res.feedback:
        print("Suggestions:")
        for s in dict.fromkeys(res.feedback):
            print(f"- {s}")

if __name__ == "__main__":
    main()
