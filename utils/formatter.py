from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def build_section(title: str, lines: list[str]) -> Panel:
    content = "\n".join(lines)

    return Panel(
        content,
        title=title,
        border_style="cyan",
        expand=True
    )


def print_analysis_result(ioc_value, ioc_type, abuse_result, otx_result, vt_result, threat_score, verdict):
    console.print()

    ioc_lines = [
        f"IOC Value : {ioc_value}",
        f"IOC Type  : {ioc_type}",
    ]
    console.print(build_section("IOC Analysis", ioc_lines))

    if abuse_result:
        abuse_lines = [
            f"Abuse Confidence Score : {abuse_result.get('abuse_confidence_score', 0)}",
            f"Total Reports          : {abuse_result.get('total_reports', 0)}",
            f"Country Code           : {abuse_result.get('country_code', 'N/A')}",
            f"ISP                    : {abuse_result.get('isp', 'N/A')}",
            f"Domain                 : {abuse_result.get('domain', 'N/A')}",
            f"Usage Type             : {abuse_result.get('usage_type', 'N/A')}",
        ]
        console.print(build_section("AbuseIPDB", abuse_lines))

    otx_lines = [
        f"Pulse Count : {otx_result.get('pulse_count', 0)}",
        f"Reputation  : {otx_result.get('reputation', 0)}",
        f"Country     : {otx_result.get('country_name', 'N/A')}",
        f"ASN         : {otx_result.get('asn', 'N/A')}",
    ]
    console.print(build_section("OTX", otx_lines))

    vt_lines = [
        f"Malicious  : {vt_result.get('malicious', 0)}",
        f"Suspicious : {vt_result.get('suspicious', 0)}",
        f"Harmless   : {vt_result.get('harmless', 0)}",
        f"Undetected : {vt_result.get('undetected', 0)}",
        f"Reputation : {vt_result.get('reputation', 0)}",
    ]
    console.print(build_section("VirusTotal", vt_lines))
    if "MALICIOUS" in verdict:
        verdict_style = "bold red"
    elif "SUSPICIOUS" in verdict:
        verdict_style = "bold yellow"
    else:
        verdict_style = "bold green"

    final_text = Text()
    final_text.append(f"Threat Score : {threat_score}\n")
    final_text.append(f"Verdict      : {verdict}", style=verdict_style)

    console.print(
        Panel(
            final_text,
            title="Final Verdict",
            border_style="cyan",
            expand=True
        )
    )