"""PressurePrint AI detection engine.

Scores a whole conversation (not single messages) for social-engineering
patterns. Works for English and Hinglish (Hindi written in Roman script).
"""
import re
from dataclasses import dataclass, field

# Each signal: label, weight (0-100 scale contribution), regex patterns (case-insensitive).
SIGNALS = {
    "impersonation": {
        "label": "Impersonation",
        "weight": 18,
        "why": "The sender claims to be an official (bank, police, courier, HR, support) to gain trust.",
        "patterns": [
            r"\b(bank|sbi|hdfc|icici|axis|paytm|phonepe|gpay|google pay)\b.*\b(team|officer|manager|executive|support|department)\b",
            r"\b(customer care|customer support|support team|helpdesk|help desk)\b",
            r"\b(police|cyber ?cell|cbi|ed officer|income tax|customs|court|trai|rbi|narcotics)\b",
            r"\b(hr|recruiter|hiring manager|talent team)\b",
            r"\b(bijli (vibhag|department)|electricity (board|department)|gas agency|telecom department)\b",
            r"\b(this is|i am|i'm|main|mai|hum)\b.{0,30}\b(from|calling from|se bol|se hu|se hoon|se bol raha|se bol rahi)\b",
            r"\b(courier|fedex|dhl|delivery)\b.*\b(parcel|package|shipment)\b",
            r"\b(your|aapka|aapki|apka|apki)\b.{0,20}\b(manager|boss|ceo|sir|madam)\b.{0,20}\b(asked|said|bola|kaha)\b",
        ],
    },
    "urgency": {
        "label": "Artificial urgency",
        "weight": 18,
        "why": "Time pressure is used so you act before you think or verify.",
        "patterns": [
            r"\b(immediately|right now|urgent|urgently|asap|at once|within \d+ ?(min|minutes|hour|hours|hrs))\b",
            r"\b(today|tonight) (only|itself)\b|\bbefore (midnight|today ends)\b",
            r"\b(in|within|next|for the next) \d+ ?(min|mins|minutes|hour|hours|hrs)\b",
            r"\b(offer|seat|slot|deal) (is )?(valid|available|open)\b.{0,30}\b(only|today|limited)\b",
            r"\b(limited (time|seats|slots)|hurry|act (now|fast)|do it now|pay now|send .{0,30} now)\b",
            r"\b(abhi|turant|jaldi|foran|aaj hi|abhi ke abhi|der mat)\b",
            r"\b(last chance|final warning|final notice|expire[sd]?|will be (blocked|suspended|closed|deactivated|cancelled))\b",
            r"\b(block ho|band ho|suspend ho|expire ho)\w*",
            r"\b(kat jayega|kat jayegi|cut ho|disconnect ho|connection (kat|band))\w*|\b(will be|to be) (disconnected|cut off)\b",
        ],
    },
    "fear": {
        "label": "Fear and threats",
        "weight": 16,
        "why": "Threats of arrest, blocking or legal action are used to scare you into complying.",
        "patterns": [
            r"\b(arrest|fir|legal action|case (file|registered)|jail|warrant|penalty|fine)\b",
            r"\b(account|card|sim|number|whatsapp)\b.{0,25}\b(blocked|suspended|frozen|deactivated|banned)\b",
            r"\b(giraftar|jail ho|case ho|kanooni|kanuni)\w*",
            r"\b(band kar (denge|dunga|di jayegi|diya jayega))\b",
        ],
    },
    "secrecy": {
        "label": "Secrecy pressure",
        "weight": 20,
        "why": "Telling you to keep it secret stops you from asking family, friends or the bank.",
        "patterns": [
            r"\b(don'?t|do not|never|dont) (tell|share this with|inform|discuss)\b.{0,25}\b(anyone|anybody|family|friends|bank|parents)\b",
            r"\b(keep (this|it) (secret|confidential|private|between us))\b",
            r"\b(confidential|secret)\b",
            r"\b(kisi ko|kisiko|kisi se)\b.{0,20}\b(mat|na)\b.{0,15}\b(batana|bolna|batao|bolo|kehna)\b",
            r"\b(ghar (walon|walo) ko|family ko)\b.{0,15}\b(mat|na)\b",
            r"\b(sirf (aap|tum) (aur|and) (main|mai|hum))\b",
        ],
    },
    "lure": {
        "label": "Reward or job lure",
        "weight": 12,
        "why": "A prize, refund or job offer is used as bait, often followed by a fee or personal details.",
        "patterns": [
            r"\b(lottery|jackpot|you (have )?won|prize|lucky draw|cashback|refund|reward points)\b",
            r"\b(work from home|part[- ]time job|earn \d+|easy money|guaranteed (income|returns?|profit))\b",
            r"\b(registration fee|processing fee|security deposit|joining fee|advance fee)\b",
            r"\b(inaam|ladki|jeeta hai|jeet gaye|ghar baithe (kamao|kamaye))\w*",
        ],
    },
    "sensitive_request": {
        "label": "Request for sensitive info or money",
        "weight": 30,
        "why": "Asking for OTP, PIN, passwords, card details or money is the core goal of most scams.",
        "patterns": [
            r"\b(otp|one[- ]time password|verification code|cvv|upi pin|atm pin|mpin|pin number|password|passcode)\b",
            r"\b(card number|debit card|credit card|account number|aadhaar|aadhar|pan (card|number)|net ?banking)\b",
            r"\b(send|transfer|pay|deposit|bhej(o|na|iye)?|transfer kar(o|na|iye)?)\b.{0,30}\b(money|amount|rs\.?|₹|rupees|paise|paisa|upi|gift card|crypto|bitcoin)\b",
            r"(₹|rs\.?|inr)\s?\d[\d,]*",
            r"\b(gift cards?|google play card|amazon (pay )?card)\b",
            r"\b(otp (share|bhej|batao|bata do|de do|dena)|share (the )?otp|otp bata)\w*",
        ],
    },
    "remote_or_link": {
        "label": "Link or remote-access request",
        "weight": 20,
        "why": "Links and remote-control apps let attackers steal data or take over your phone.",
        "patterns": [
            r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen ?share)\b",
            r"\b(install|download)\b.{0,25}\b(app|apk|software|application)\b",
            r"\b(click|tap|open)\b.{0,25}\b(link|url)\b",
            r"https?://\S+|\b(bit\.ly|tinyurl|t\.co)/\S+",
            r"\b(link (par|pe) click|click kar(o|na|iye)|apk (install|download))\w*",
        ],
    },
    "trust_building": {
        "label": "Trust building",
        "weight": 4,
        "why": "Friendly or reassuring language is used early to lower your guard.",
        "patterns": [
            r"\b(don'?t worry|dont worry|trust me|i will help you|we will help|happy to help|no problem)\b",
            r"\b(chinta mat|tension mat|ghabrao mat|bharosa|main (aapki )?madad)\w*",
        ],
    },
}

# Stage order used to detect escalation across messages.
STAGE = {
    "trust_building": 1, "impersonation": 1, "lure": 1,
    "urgency": 2, "fear": 2, "secrecy": 2,
    "remote_or_link": 3, "sensitive_request": 3,
}

ADVICE = {
    "sensitive_request": "Never share OTP, PIN, CVV or passwords with anyone, not even someone claiming to be from your bank.",
    "remote_or_link": "Do not click unknown links or install apps like AnyDesk or TeamViewer when asked by someone else.",
    "impersonation": "Verify who they are by calling the official number printed on your card or the company website, not the number they gave you.",
    "urgency": "Pause. Real banks and officials do not force you to act within minutes.",
    "fear": "Police and banks do not threaten arrest or blocking over chat. Hang up and verify independently.",
    "secrecy": "Talk to a family member or friend about this chat. Scammers ask for secrecy so no one can warn you.",
    "lure": "Prizes, easy jobs and refunds that ask for a fee first are scams. Do not pay anything upfront.",
}

COMPILED = {k: [re.compile(p, re.I) for p in v["patterns"]] for k, v in SIGNALS.items()}


@dataclass
class Message:
    index: int
    sender: str
    text: str


def parse_chat(raw: str):
    """Split a pasted chat into messages. Handles 'Name: text' and WhatsApp-style lines."""
    msgs = []
    wa = re.compile(r"^\[?\d{1,2}/\d{1,2}/\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[APap][Mm])?\]?\s*-?\s*")
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        line = wa.sub("", line)
        sender, text = "", line
        m = re.match(r"^([A-Za-z][\w .'-]{0,24}):\s+(.*)$", line)
        if m and not m.group(1).lower().startswith(("http", "https")):
            sender, text = m.group(1).strip(), m.group(2).strip()
        if text:
            msgs.append(Message(len(msgs) + 1, sender, text))
    return msgs


def _level(score):
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _analyze_msgs(msgs):
    hits = {}          # signal -> list of message indices
    per_message = {}   # index -> list of signals
    for m in msgs:
        for sig, pats in COMPILED.items():
            if any(p.search(m.text) for p in pats):
                hits.setdefault(sig, []).append(m.index)
                per_message.setdefault(m.index, []).append(sig)

    # Base score: each distinct signal counts once, with a small bonus for repeats.
    base = 0.0
    for sig, idxs in hits.items():
        w = SIGNALS[sig]["weight"]
        base += w + min(len(idxs) - 1, 2) * (w * 0.15)

    # Escalation: earlier trust/pressure followed by a later sensitive ask or link.
    escalation = False
    first_stage = {}
    for sig, idxs in hits.items():
        first_stage[sig] = min(idxs)
    ask_idx = min([first_stage[s] for s in ("sensitive_request", "remote_or_link") if s in first_stage], default=None)
    pressure_before = []
    if ask_idx:
        pressure_before = [s for s in ("urgency", "fear", "secrecy", "impersonation", "lure")
                           if s in first_stage and first_stage[s] <= ask_idx]
        # Needs pressure on an earlier message, or a combo, to count as escalation.
        earlier = [s for s in pressure_before if first_stage[s] < ask_idx]
        if earlier or len(pressure_before) >= 2:
            escalation = True
    bonus = 0
    if escalation:
        bonus = 12 + 6 * max(0, len(set(pressure_before)) - 1)
    # Combo bonus: secrecy + urgency together is a classic scam signature.
    if "secrecy" in hits and "urgency" in hits:
        bonus += 8

    # A sensitive ask alone, with no pressure signals, stays modest (could be legitimate).
    score = base + bonus
    if set(hits) <= {"sensitive_request", "trust_building"} and len(msgs) <= 2:
        score = min(score, 34)
    score = int(max(0, min(100, round(score))))
    level = _level(score)

    signals = []
    for sig, idxs in sorted(hits.items(), key=lambda kv: -SIGNALS[kv[0]]["weight"]):
        if sig == "trust_building" and len(hits) == 1:
            continue
        signals.append({
            "key": sig,
            "label": SIGNALS[sig]["label"],
            "why": SIGNALS[sig]["why"],
            "messages": idxs,
        })

    reasons = [f"{s['label']} found in message{'s' if len(s['messages']) > 1 else ''} "
               f"{', '.join('#' + str(i) for i in s['messages'])}. {s['why']}" for s in signals]
    if escalation:
        reasons.append("Escalation pattern: pressure or false authority comes first, then a request for "
                       "sensitive information, money or a risky action. Each message may look harmless alone, "
                       "but together they follow a common scam script.")

    advice = [ADVICE[s["key"]] for s in signals if s["key"] in ADVICE]
    if level == "High":
        advice.insert(0, "Stop replying now. Do not share anything or send any money.")
        advice.append("If you already shared an OTP or money, call your bank immediately and report at cybercrime.gov.in or call 1930.")
    elif level == "Medium":
        advice.insert(0, "Be careful. Verify this person through an official channel before responding.")
    else:
        advice = ["No strong warning signs found. Stay alert, and never share OTPs or PINs with anyone."]

    summary = {
        "High": "This conversation matches a common social engineering pattern.",
        "Medium": "This conversation shows some warning signs. Verify before you act.",
        "Low": "No strong social engineering pattern found.",
    }[level]

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "escalation": escalation,
        "signals": signals,
        "reasons": reasons,
        "advice": advice,
        "messages": [
            {"index": m.index, "sender": m.sender, "text": m.text,
             "flags": [SIGNALS[s]["label"] for s in per_message.get(m.index, []) if s != "trust_building"]}
            for m in msgs
        ],
    }


def analyze(raw: str):
    """Analyze a pasted chat. Also returns a timeline: the risk score after each message."""
    msgs = parse_chat(raw)
    if not msgs:
        return {"error": "Please paste a conversation with at least one message."}
    result = _analyze_msgs(msgs)
    result["timeline"] = [
        {"index": i, "score": _analyze_msgs(msgs[:i])["score"]}
        for i in range(1, len(msgs) + 1)
    ]
    return result
