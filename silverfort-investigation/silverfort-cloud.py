#!/usr/bin/env python3
"""
Silverfort / Okta cloud-log investigation helper.

Usage:
    python silverfort-cloud.py "/path/to/Okta-system-log.csv"

If no path is supplied, the script looks for a CSV whose filename contains
"okta" or "cloud" in the current directory. It prints focused summaries and
does not modify the source data.
"""
from pathlib import Path
import sys
import pandas as pd

SUSPICIOUS_IPS = ["79.177.131.197", "212.97.69.32"]
API_TOKEN_ID = "00T1wgdc76e1BvZIa5d7"
KEY_EVENTS = [
    "system.idp.lifecycle.read_client_secret",
    "system.org.rate_limit.warning",
    "policy.rule.add",
    "policy.lifecycle.create",
    "group.lifecycle.create",
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",
    "user.authentication.verify",
    "user.mfa.factor.activate",
    "app.oauth2.token.grant.access_token",
    "app.oauth2.token.grant.id_token",
]


def choose_csv():
    if len(sys.argv) > 1:
        path = Path(sys.argv[1]).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"CSV not found: {path}")
        return path
    candidates = [
        p for p in Path.cwd().glob("*.csv")
        if "okta" in p.name.lower() or "cloud" in p.name.lower()
    ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise FileNotFoundError(
            "No CSV path supplied and no CSV containing 'okta' or 'cloud' "
            "found in the current directory. Pass the CSV path as an argument."
        )
    raise RuntimeError(
        "More than one possible CSV found. Run the script with the exact path:\n"
        + "\n".join(str(p) for p in candidates)
    )


def show(title, frame, columns, limit=100):
    print(f"\n{'=' * 90}\n{title}\n{'=' * 90}")
    available = [c for c in columns if c in frame.columns]
    if frame.empty:
        print("No matching rows.")
    elif not available:
        print("Matching rows found, but none of the requested columns exist.")
    else:
        print(frame[available].head(limit).to_string(index=False))
        if len(frame) > limit:
            print(f"... showing {limit} of {len(frame)} rows")


def main():
    path = choose_csv()
    dfcloud = pd.read_csv(path, low_memory=False)
    print(f"Loaded: {path}")
    print(f"Rows: {len(dfcloud):,} | Columns: {len(dfcloud.columns)}")
    print("\nAvailable columns:")
    print("\n".join(map(str, dfcloud.columns)))

    if "timestamp" in dfcloud.columns:
        dfcloud["timestamp"] = pd.to_datetime(
            dfcloud["timestamp"], errors="coerce", utc=True
        )
        dfcloud = dfcloud.sort_values("timestamp")

    event_col = "event_type"
    ip_col = "client.ip_address"
    actor_col = "actor.alternate_id"
    result_col = "outcome.result"
    reason_col = "outcome.reason"
    uri_col = "debug_context.debug_data.request_uri"
    root_token_col = "transaction.detail.root_api_token_id"
    request_token_col = "transaction.detail.request_api_token_id"

    base_cols = [
        "timestamp", event_col, result_col, reason_col, actor_col, ip_col,
        "target0.display_name", "target0.alternate_id", uri_col,
        "authentication_context.root_session_id", root_token_col,
        request_token_col,
    ]

    # 1. High-priority activity from the two IPs investigated in the exercise.
    if ip_col in dfcloud.columns:
        ip_events = dfcloud[dfcloud[ip_col].isin(SUSPICIOUS_IPS)]
        show("Events from suspicious IPs", ip_events, base_cols, limit=200)

        for ip in SUSPICIOUS_IPS:
            subset = dfcloud[dfcloud[ip_col].eq(ip)]
            show(f"Timeline for {ip}", subset, base_cols, limit=200)

    # 2. IdP client-secret reads and rate-limit warnings.
    if event_col in dfcloud.columns:
        secret_events = dfcloud[
            dfcloud[event_col].astype(str).str.contains(
                "read_client_secret", case=False, na=False
            )
        ]
        show("IdP client-secret read events", secret_events, base_cols, limit=200)

        rate_events = dfcloud[
            dfcloud[event_col].astype(str).str.contains(
                "rate_limit.warning", case=False, na=False
            )
        ]
        show("API rate-limit warning events", rate_events, base_cols, limit=200)

        key_events = dfcloud[
            dfcloud[event_col].astype(str).isin(KEY_EVENTS)
        ]
        show("Selected authentication, policy and token events",
             key_events, base_cols, limit=200)

