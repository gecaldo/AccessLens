# Contains the actual audit rules and turns anything suspicious into a report finding.

from datetime import datetime, timezone

from .privilege import (
    DEFAULT_PRIVILEGED_GROUPS,
    build_name_lookup,
    find_privilege_paths,
    readable_path,
)


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def parse_date(value):
    if not value:
        return None

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def make_finding(rule_id, severity, title, account, evidence, recommendation):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "account": account,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def audit_snapshot(data, stale_days=90, now=None, privileged_group_names=None):
    privileged_group_names = privileged_group_names or DEFAULT_PRIVILEGED_GROUPS
    now = now or datetime.now(timezone.utc)

    paths_by_user = find_privilege_paths(data, privileged_group_names)
    names = build_name_lookup(data)
    users_by_id = {user["id"]: user for user in data["users"]}
    findings = []

    # R001-R006 are checks for users that can reach at least one privileged group.
    for user_id, paths in paths_by_user.items():
        if not paths:
            continue

        user = users_by_id[user_id]
        account = user["sam_account_name"]
        target_names = sorted({path["target_name"] for path in paths})

        # R001 - disabled but still privileged
        if not user.get("enabled", True):
            findings.append(
                make_finding(
                    "R001",
                    "HIGH",
                    "Disabled account still has privileged access",
                    account,
                    "Privileged groups: " + ", ".join(target_names),
                    "Review the account and remove privileged memberships that are no longer needed.",
                )
            )

        # R002 - privileged account with a non-expiring password
        if user.get("password_never_expires") is True:
            findings.append(
                make_finding(
                    "R002",
                    "HIGH",
                    "Privileged account has a non-expiring password",
                    account,
                    "PasswordNeverExpires=True; privileged groups: " + ", ".join(target_names),
                    "Review the password setting and confirm it matches the account's intended use.",
                )
            )

        # R003 - privileged account where a password is not required
        if user.get("password_not_required") is True:
            findings.append(
                make_finding(
                    "R003",
                    "CRITICAL",
                    "Privileged account does not require a password",
                    account,
                    "PasswordNotRequired=True; privileged groups: " + ", ".join(target_names),
                    "Require authentication and review why this account was configured without a password requirement.",
                )
            )

        # R004 - enabled privileged account that has not logged in recently
        last_logon = parse_date(user.get("last_logon_date"))

        if user.get("enabled", True) and last_logon is not None:
            inactive_days = (now - last_logon).days

            if inactive_days >= stale_days:
                findings.append(
                    make_finding(
                        "R004",
                        "MEDIUM",
                        "Stale privileged account",
                        account,
                        f"Last logon was {inactive_days} days ago; privileged groups: "
                        + ", ".join(target_names),
                        "Confirm the account is still needed and remove or reduce access if it is no longer active.",
                    )
                )

        # R005 - one account reaches more than one privileged group
        if len(target_names) >= 2:
            findings.append(
                make_finding(
                    "R005",
                    "MEDIUM",
                    "Account reaches multiple privileged groups",
                    account,
                    "Reachable privileged groups: " + ", ".join(target_names),
                    "Review whether the account needs every privileged role and keep only the access it actually needs.",
                )
            )

        # R006 - access comes through one or more nested groups
        indirect_paths = [path for path in paths if not path["direct"]]

        if indirect_paths:
            shortest_path = min(indirect_paths, key=lambda item: len(item["path"]))

            findings.append(
                make_finding(
                    "R006",
                    "MEDIUM",
                    "Indirect privileged access through nested groups",
                    account,
                    "Path: " + readable_path(shortest_path["path"], names),
                    "Review the nested group path and make sure the inherited privileged access is intentional.",
                )
            )

    # R007 - check whether the built-in Guest account is enabled
    for user in data["users"]:
        sid = user.get("sid") or ""
        account_name = user.get("sam_account_name", "")
        is_guest = sid.endswith("-501") or account_name.lower() == "guest"

        if is_guest and user.get("enabled") is True:
            findings.append(
                make_finding(
                    "R007",
                    "HIGH",
                    "Built-in Guest account is enabled",
                    account_name,
                    f"Enabled=True; SID={sid or 'unknown'}",
                    "Disable the Guest account unless there is a specific reason it needs to stay enabled.",
                )
            )

    # R008 - check for groups nested directly inside a privileged group
    privileged_group_ids = {
        group["id"]
        for group in data["groups"]
        if group["name"] in privileged_group_names
    }
    all_group_ids = {group["id"] for group in data["groups"]}

    for group in data["groups"]:
        if group["id"] not in privileged_group_ids:
            continue

        for member_id in group.get("members", []):
            if member_id not in all_group_ids:
                continue

            nested_name = names.get(member_id, member_id)

            findings.append(
                make_finding(
                    "R008",
                    "LOW",
                    "Nested group inside a privileged group",
                    nested_name,
                    f"{nested_name} is nested in {group['name']}",
                    "Review the nested group because its members can inherit access from the parent group.",
                )
            )

    findings.sort(
        key=lambda item: (
            -SEVERITY_ORDER[item["severity"]],
            item["rule_id"],
            item["account"].lower(),
        )
    )

    return findings
