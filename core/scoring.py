def calculate_ip_score(
    abuse_confidence_score: int = 0,
    otx_pulse_count: int = 0,
    vt_malicious: int = 0,
    vt_suspicious: int = 0
) -> int:
    score = 0

    score += min(abuse_confidence_score, 100) * 0.45

    if otx_pulse_count >= 10:
        score += 20
    elif otx_pulse_count >= 5:
        score += 12
    elif otx_pulse_count >= 1:
        score += 6

    vt_score = (vt_malicious * 7) + (vt_suspicious * 3)
    score += min(vt_score, 35)

    return int(min(score, 100))


def calculate_generic_score(
    otx_pulse_count: int = 0,
    vt_malicious: int = 0,
    vt_suspicious: int = 0
) -> int:
    score = 0

    if otx_pulse_count >= 10:
        score += 30
    elif otx_pulse_count >= 5:
        score += 20
    elif otx_pulse_count >= 1:
        score += 10

    vt_score = (vt_malicious * 10) + (vt_suspicious * 4)
    score += min(vt_score, 70)

    return int(min(score, 100))


def get_verdict(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"