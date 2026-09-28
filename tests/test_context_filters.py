from app.models import Evidence, Observable
from app.services.context_filters import (
    detect_artifact_platform,
    evidence_platform,
    has_clean_reputation,
    incompatible_evidence_ids,
    known_infrastructure_owner,
)


def _metadata(file_type: str) -> Evidence:
    return Evidence(
        id="E000",
        source="virustotal",
        kind="file_metadata",
        value={"type_description": file_type},
    )


def _command(evidence_id: str, value: str) -> Evidence:
    return Evidence(
        id=evidence_id,
        source="virustotal",
        kind="sandbox_command",
        value=value,
    )


def test_detects_platform_from_file_type() -> None:
    assert detect_artifact_platform([_metadata("Mach-O")]) == "macos"
    assert detect_artifact_platform([_metadata("Win32 EXE")]) == "windows"
    assert detect_artifact_platform([_metadata("ELF")]) == "linux"
    assert detect_artifact_platform([_metadata("PDF")]) is None


def test_conflicting_file_types_are_not_resolved() -> None:
    assert (
        detect_artifact_platform(
            [_metadata("Mach-O"), _metadata("Win32 EXE")]
        )
        is None
    )


def test_classifies_evidence_platform() -> None:
    windows = [
        '"C:\\Windows\\system32\\rundll32.exe" shell32.dll,OpenAs_RunDLL',
        "wininet.HttpSendRequestA",
        "advapi32.RegOpenKeyExW",
        "\\Sessions\\1\\BaseNamedObjects",
    ]
    macos = [
        "sh -c launchctl load ~/Library/LaunchAgents/com.root.x.plist",
        "/private/var/root/Library/gfskjsnghdjsvuxj",
        "xpcproxy com.apple.PerfPowerServices",
    ]

    for value in windows:
        assert evidence_platform(_command("E1", value)) == "windows", value

    for value in macos:
        assert evidence_platform(_command("E1", value)) == "macos", value

    assert evidence_platform(_command("E1", "killall Terminal")) is None


def test_windows_noise_is_incompatible_with_macho() -> None:
    evidence = [
        _metadata("Mach-O"),
        _command("E1", "C:\\Users\\user\\AppData\\Local\\Temp\\x"),
        _command("E2", "launchctl load /Users/u/Library/LaunchAgents/a.plist"),
        _command("E3", "killall Terminal"),
        _command("E4", "crontab -l"),
    ]

    assert incompatible_evidence_ids(evidence) == {"E1"}


def test_no_filter_without_known_platform() -> None:
    evidence = [
        _command("E1", "C:\\Windows\\system32\\cmd.exe"),
    ]

    assert incompatible_evidence_ids(evidence) == set()


def test_known_infrastructure_owner() -> None:
    assert known_infrastructure_owner("ip", "17.253.7.201") == "Apple"
    assert known_infrastructure_owner("ip", "151.101.3.6") == "Fastly CDN"
    assert known_infrastructure_owner("ip", "23.4.43.62") == "Akamai"
    assert (
        known_infrastructure_owner(
            "domain",
            "h3.apis.apple.map.fastly.net",
        )
        == "Apple via Fastly CDN"
    )
    # Nuvem genérica também hospeda C2 e não entra na lista.
    assert known_infrastructure_owner("ip", "54.173.154.19") is None
    assert known_infrastructure_owner("domain", "notapple.com") is None
    assert known_infrastructure_owner("ip", "not-an-ip") is None


def test_clean_reputation_requires_stats() -> None:
    def observable(context: dict) -> Observable:
        return Observable(
            type="ip",
            value="203.0.113.10",
            source="virustotal",
            context=context,
        )

    assert has_clean_reputation(
        observable({"last_analysis_stats": {"malicious": 0}})
    )
    assert not has_clean_reputation(
        observable({"last_analysis_stats": {"malicious": 3}})
    )
    assert not has_clean_reputation(observable({}))
