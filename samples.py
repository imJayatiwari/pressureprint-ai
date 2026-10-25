SAMPLES = {
    "Fake bank officer (English)": [
        "Scammer: Hello sir, this is the SBI customer care team. Don't worry, we will help you.",
        "Scammer: Your account will be blocked today because your KYC has expired.",
        "Scammer: To avoid this, share the OTP you just received immediately.",
        "Scammer: Please don't tell anyone about this call, it is confidential.",
    ],
    "Fake bank officer (Hinglish)": [
        "Caller: Namaste, main HDFC bank se bol raha hoon. Aapka account block ho jayega.",
        "Caller: Abhi turant apna OTP bata do, warna aaj hi band ho jayega.",
        "Caller: Ye baat kisi ko mat batana, ye confidential hai.",
    ],
    "Fake job offer": [
        "Recruiter: Congratulations! You are selected for a work from home part time job. Earn 5000 daily.",
        "Recruiter: Please pay a registration fee of Rs 999 to confirm your seat.",
        "Recruiter: Offer valid for the next 30 minutes only. Send money on this UPI now.",
    ],
    "Fake police / arrest threat": [
        "Caller: This is Mumbai cyber cell. A case has been registered against your Aadhaar.",
        "Caller: You will be arrested today unless you cooperate. Install AnyDesk so we can verify.",
        "Caller: Do not tell your family. Transfer Rs 50000 for the security deposit.",
    ],
    "Normal chat with a friend": [
        "Riya: Hey, are we meeting for lunch tomorrow?",
        "Me: Yes! Same cafe at 1 pm?",
        "Riya: Perfect, see you there. I'll bring the notes.",
    ],
    "Real bank alert (safe)": [
        "HDFC Bank: Your OTP for the transaction is 482913. Do not share it with anyone.",
    ],
}


def as_text(name):
    return "\n".join(SAMPLES[name])
