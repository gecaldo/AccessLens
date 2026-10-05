# Handles group membership relationships and finds direct/indirect paths to admin groups.

from collections import defaultdict, deque


DEFAULT_PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
}


def build_membership_map(data):
    # member -> groups that member directly belongs to
    membership_map = defaultdict(list)

    for group in data["groups"]:
        group_id = group["id"]

        for member_id in group.get("members", []):
            membership_map[member_id].append(group_id)

    return membership_map


def get_privileged_groups(data, privileged_group_names):
    privileged = {}

    for group in data["groups"]:
        if group["name"] in privileged_group_names:
            privileged[group["id"]] = group["name"]

    return privileged


def find_privilege_paths(data, privileged_group_names=None, max_depth=8):
    # BFS keeps the first path we find to a privileged group, which is the shortest one.
    privileged_group_names = privileged_group_names or DEFAULT_PRIVILEGED_GROUPS
    membership_map = build_membership_map(data)
    privileged_groups = get_privileged_groups(data, privileged_group_names)

    results = {}

    for user in data["users"]:
        user_id = user["id"]
        queue = deque([(user_id, [user_id])])
        visited_depth = {user_id: 0}
        found_paths = {}

        while queue:
            current_id, path = queue.popleft()
            depth = len(path) - 1

            if depth > max_depth:
                continue

            if current_id in privileged_groups and current_id != user_id:
                if current_id not in found_paths:
                    found_paths[current_id] = path

            for next_group in membership_map.get(current_id, []):
                next_depth = depth + 1

                if next_depth > max_depth:
                    continue

                if next_group not in visited_depth or next_depth < visited_depth[next_group]:
                    visited_depth[next_group] = next_depth
                    queue.append((next_group, path + [next_group]))

        results[user_id] = [
            {
                "target_id": group_id,
                "target_name": privileged_groups[group_id],
                "path": path,
                "direct": len(path) == 2,
            }
            for group_id, path in found_paths.items()
        ]

    return results


def build_name_lookup(data):
    names = {}

    for user in data["users"]:
        names[user["id"]] = user["sam_account_name"]

    for group in data["groups"]:
        names[group["id"]] = group["name"]

    return names


def readable_path(path, names):
    return " -> ".join(names.get(item, item) for item in path)
