"""Analyze Linux authentication and UFW firewall logs.

Run from the command line with:

    python3 log_analysis.py --logs-dir logs
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, TextIO


DEFAULT_LOGS_DIR = Path("logs")
INVALID_USER_RE = re.compile(
    r"\bInvalid user (?P<username>\S+) from (?P<ip>[0-9A-Fa-f:.]+)\b"
)
UFW_SOURCE_RE = re.compile(r"\bSRC=(?P<ip>[0-9A-Fa-f:.]+)\b")


@dataclass(frozen=True)
class AnalysisResult:
    """Summary statistics for one directory of log files."""

    files_processed: int
    auth_files_processed: int
    ufw_files_processed: int
    invalid_login_attempts: int
    unique_invalid_usernames: int
    unique_invalid_login_ips: int
    unique_scanning_ips: int
    unique_overlap_ips: int
    top_invalid_usernames: list[tuple[str, int]]
    overlap_ips: list[str]


def _matching_files(logs_dir: Path | str, prefix: str) -> list[Path]:
    directory = Path(logs_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Log directory does not exist: {directory}")

    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.name.startswith(prefix)
    )


def _open_log(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return path.open(mode="r", encoding="utf-8", errors="replace")


def _read_lines(paths: Iterable[Path]) -> Iterable[str]:
    for path in paths:
        with _open_log(path) as log_file:
            yield from log_file


def get_user_auth_times(
    user_id: str, logs_dir: Path | str = DEFAULT_LOGS_DIR
) -> list[str]:
    """Return syslog timestamps for authentication lines containing ``user_id``."""

    if not user_id:
        raise ValueError("user_id must not be empty")

    user_pattern = re.compile(rf"(?<!\w){re.escape(user_id)}(?!\w)")
    return [
        line[:15]
        for line in _read_lines(_matching_files(logs_dir, "auth.log"))
        if user_pattern.search(line)
    ]


def _invalid_login_records(
    logs_dir: Path | str = DEFAULT_LOGS_DIR,
) -> Iterable[tuple[str, str]]:
    for line in _read_lines(_matching_files(logs_dir, "auth.log")):
        match = INVALID_USER_RE.search(line)
        if match:
            yield match.group("username"), match.group("ip")


def get_invalid_logins(
    logs_dir: Path | str = DEFAULT_LOGS_DIR,
) -> dict[str, int]:
    """Map each invalid username to its number of failed login attempts."""

    return dict(Counter(username for username, _ in _invalid_login_records(logs_dir)))


def get_invalid_login_ips(
    logs_dir: Path | str = DEFAULT_LOGS_DIR,
) -> set[str]:
    """Return unique source IPs associated with invalid-user login attempts."""

    return {ip for _, ip in _invalid_login_records(logs_dir)}


def get_scanning_ips(logs_dir: Path | str = DEFAULT_LOGS_DIR) -> set[str]:
    """Return unique source IPs found in UFW blocked-traffic records."""

    scanning_ips: set[str] = set()
    for line in _read_lines(_matching_files(logs_dir, "ufw.log")):
        if "[UFW BLOCK]" not in line:
            continue
        match = UFW_SOURCE_RE.search(line)
        if match:
            scanning_ips.add(match.group("ip"))
    return scanning_ips


def compare_invalid_ips(logs_dir: Path | str = DEFAULT_LOGS_DIR) -> list[str]:
    """Return sorted IPs seen in both invalid logins and UFW blocks."""

    return sorted(get_invalid_login_ips(logs_dir) & get_scanning_ips(logs_dir))


def compare_invalid_IPs(logs_dir: Path | str = DEFAULT_LOGS_DIR) -> list[str]:
    """Backward-compatible alias for the original public function name."""

    return compare_invalid_ips(logs_dir)


def analyze_logs(
    logs_dir: Path | str = DEFAULT_LOGS_DIR, top: int = 10
) -> AnalysisResult:
    """Analyze all supported logs and return a reproducible summary."""

    if top < 1:
        raise ValueError("top must be at least 1")

    auth_files = _matching_files(logs_dir, "auth.log")
    ufw_files = _matching_files(logs_dir, "ufw.log")
    if not auth_files and not ufw_files:
        raise FileNotFoundError(
            f"No auth.log* or ufw.log* files found in {Path(logs_dir)}"
        )

    invalid_records = list(_invalid_login_records(logs_dir))
    invalid_users = Counter(username for username, _ in invalid_records)
    invalid_ips = {ip for _, ip in invalid_records}
    scanning_ips = get_scanning_ips(logs_dir)
    overlap_ips = sorted(invalid_ips & scanning_ips)

    return AnalysisResult(
        files_processed=len(auth_files) + len(ufw_files),
        auth_files_processed=len(auth_files),
        ufw_files_processed=len(ufw_files),
        invalid_login_attempts=len(invalid_records),
        unique_invalid_usernames=len(invalid_users),
        unique_invalid_login_ips=len(invalid_ips),
        unique_scanning_ips=len(scanning_ips),
        unique_overlap_ips=len(overlap_ips),
        top_invalid_usernames=invalid_users.most_common(top),
        overlap_ips=overlap_ips,
    )


def _print_text(result: AnalysisResult, top: int) -> None:
    print(f"Files processed: {result.files_processed}")
    print(f"  Authentication logs: {result.auth_files_processed}")
    print(f"  UFW logs: {result.ufw_files_processed}")
    print(f"Invalid login attempts: {result.invalid_login_attempts}")
    print(f"Unique invalid usernames: {result.unique_invalid_usernames}")
    print(f"Unique invalid-login IPs: {result.unique_invalid_login_ips}")
    print(f"Unique UFW blocked IPs: {result.unique_scanning_ips}")
    print(f"Unique overlap IPs: {result.unique_overlap_ips}")
    print(f"Top {top} invalid usernames: {result.top_invalid_usernames}")
    print(f"Overlap IPs: {result.overlap_ips}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze Linux auth.log and ufw.log files for invalid usernames "
            "and source-IP overlap."
        )
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=DEFAULT_LOGS_DIR,
        help="directory containing auth.log* and ufw.log* files (default: logs)",
    )
    parser.add_argument(
        "--user",
        help="also print authentication timestamps associated with this username",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="number of invalid usernames to include (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="write the summary as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze_logs(args.logs_dir, args.top)
        user_times = (
            get_user_auth_times(args.user, args.logs_dir) if args.user else None
        )
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))

    if args.json:
        payload = asdict(result)
        if args.user:
            payload["user_query"] = {
                "username": args.user,
                "timestamps": user_times,
            }
        print(json.dumps(payload, indent=2))
    else:
        _print_text(result, args.top)
        if args.user:
            print(f"Authentication timestamps for {args.user}: {user_times}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
