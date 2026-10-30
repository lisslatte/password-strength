"""
Password Strength + Breach Checker (Streamlit)

Run:
    pip install streamlit requests
    streamlit run streamlit_app.py

Privacy: breach lookups use the Have I Been Pwned "Pwned Passwords" range API
with k-anonymity. Only the first 5 characters of the password's SHA-1 hash are
sent to HIBP; the full password/hash never leaves this machine.
"""

import hashlib
import math
import re
import string

import requests
import streamlit as st

HIBP_URL = "https://api.pwnedpasswords.com/range/"

COMMON = {
    "password", "123456", "123456789", "12345678", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "football", "login", "passw0rd", "qwerty123",
    "1q2w3e4r", "sunshine", "princess", "master", "hello", "freedom",
}

SEQUENCES = [
    string.ascii_lowercase, string.digits,
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]

LEVELS = [
    ("Very weak", "#d92d20"),
    ("Weak", "#f04438"),
    ("Fair", "#f79009"),
    ("Strong", "#17b26a"),
    ("Very strong", "#039855"),
]


# ---------------------------------------------------------------- strength --
def has_sequence(pw: str, run: int = 4) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in low:
                    return True
    return False


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    if seconds >= 31536000 * 1e9:
        return "billions of years+"
    for name, size in [("year", 31536000), ("day", 86400), ("hour", 3600),
                       ("minute", 60), ("second", 1)]:
        if seconds >= size:
            n = int(seconds // size)
            return f"{n:,} {name}{'s' if n != 1 else ''}"
    return "instantly"


def analyze_strength(pw: str) -> dict:
    feedback = []

    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw): pool += 10
    if re.search(r"[^\w\s]|_", pw): pool += 33
    if re.search(r"\s", pw): pool += 1

    entropy = len(pw) * math.log2(pool) if pool else 0

    if pw.lower() in COMMON:
        entropy = min(entropy, 10)
        feedback.append("This is one of the most common passwords.")
    if re.search(r"(.)\1{2,}", pw):
        entropy *= 0.8
        feedback.append("Avoid repeated characters (e.g. 'aaa').")
    if has_sequence(pw):
        entropy *= 0.8
        feedback.append("Avoid sequences like 'abcd', '1234' or 'qwerty'.")
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[^\w\s]?", pw):
        entropy *= 0.85
        feedback.append("Word + number patterns are easy to guess.")

    if len(pw) < 12:
        feedback.append("Use at least 12 characters (14+ is better).")
    if not re.search(r"[A-Z]", pw) or not re.search(r"[a-z]", pw):
        feedback.append("Mix upper- and lowercase letters.")
    if not re.search(r"\d", pw):
        feedback.append("Add some digits.")
    if not re.search(r"[^\w\s]|_", pw):
        feedback.append("Add a symbol.")
    if len(pw) >= 16 and not feedback:
        feedback.append("Looks good. A long passphrase is great.")

    crack_seconds = (2 ** entropy) / 2 / 1e10  # 10 billion guesses/sec offline

    if entropy < 28: score = 0
    elif entropy < 36: score = 1
    elif entropy < 60: score = 2
    elif entropy < 80: score = 3
    else: score = 4

    return {"score": score, "entropy": round(entropy, 1),
            "crack_time": format_duration(crack_seconds), "feedback": feedback}


# ------------------------------------------------------------------ breach --
# Deliberately NOT cached: caching would keep password-derived data in memory.
def check_breach(pw: str) -> dict:
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            HIBP_URL + prefix,
            headers={"Add-Padding": "true", "User-Agent": "pw-checker-demo"},
            timeout=8,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        return {"checked": False, "pwned": False, "count": 0,
                "error": f"Breach lookup failed: {e.__class__.__name__}"}

    for line in r.text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            n = int(count.strip() or 0)
            if n > 0:  # padded entries have count 0
                return {"checked": True, "pwned": True, "count": n}
    return {"checked": True, "pwned": False, "count": 0}


# --------------------------------------------------------------------- UI --
st.set_page_config(page_title="Password Checker", page_icon="🔐", layout="centered")

st.title("🔐 Password Checker")
st.caption("Check password strength and see whether it has appeared in a known data breach.")

show = st.checkbox("Show password", value=False)
pw = st.text_input(
    "Password",
    type="default" if show else "password",
    max_chars=256,
    placeholder="Type a password and press Enter",
    autocomplete="off",
)

if pw:
    strength = analyze_strength(pw)
    with st.spinner("Checking breach database..."):
        breach = check_breach(pw)

    score = strength["score"]
    label, color = LEVELS[score]
    if breach["pwned"]:
        score, label, color = 0, "Compromised", LEVELS[0][1]

    st.markdown(
        f"<h3 style='color:{color};margin-bottom:0'>{label}</h3>",
        unsafe_allow_html=True,
    )
    st.progress((max(score, 1)) / 4 if not breach["pwned"] else 0.25)

    c1, c2 = st.columns(2)
    c1.metric("Entropy", f"{strength['entropy']} bits")
    c2.metric("Offline crack time", strength["crack_time"])

    if breach["pwned"]:
        st.error(
            f"Found in data breaches **{breach['count']:,}** times. "
            "Do not use this password."
        )
    elif breach["checked"]:
        st.success("Not found in any known breach.")
    else:
        st.warning(breach.get("error", "Breach check unavailable."))

    if strength["feedback"]:
        st.markdown("**Suggestions**")
        for tip in strength["feedback"]:
            st.markdown(f"- {tip}")

st.divider()
st.caption(
    "Breach data: Have I Been Pwned. Only the first 5 characters of the password's "
    "SHA-1 hash are sent (k-anonymity). Your password is never stored or logged."
)
