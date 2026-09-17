def run_task2():
    users = {
        "ciso_office": {"role": "ciso", "clearance": 4, "department": "Executive",
                        "active": True},
        "threat_hunter": {"role": "threat_analyst", "clearance": 3, "department":
            "Threat Intel", "active": True},
        "junior_dev": {"role": "junior_developer", "clearance": 2, "department":
            "Development", "active": True},
        "visitor_acc": {"role": "visitor", "clearance": 1, "department": "Guest",
                        "active": True},
        "legacy_sys": {"role": "legacy", "clearance": 2, "department": "Legacy",
                       "active": False}
    }
    resources = [("threat_intelligence", 4), ("malware_samples", 3),
                 ("coding_guidelines", 2), ("visitor_wifi", 1), ("strategic_plans", 4),
                 ("demo_environment", 1), ("risk_assessments", 3), ("crypto_keys", 4),
                 ("api_documentation", 2), ("guest_portal", 1)]
    security_levels = ("Guest", "Employee", "Privileged", "Executive")
    blocked_users = {"legacy_sys", "malicious_user", "expired_guest"}

    print("Список ресурсів системи:")
    print("-" * 45)
    for resource_name, security_level in resources:
        level_name = security_levels[security_level - 1]
        print(f"{resource_name:<25}: {level_name}")
    print("-" * 45)
    def check_access(username: str, resource_level: int) -> str:
        if username not in users:
            return "DENY (User not found)"
        user = users[username]
        if username in blocked_users:
            return "DENY (User is blocked)"
        if not user["active"]:
            return "DENY (Account inactive)"
        if user["clearance"] >= resource_level:
            return "ALLOW"
        return "DENY (Insufficient clearance)"
    print("\nРезультати перевірки доступу:")
    print("=" * 70)
    for username in users:
        for resource_name, resource_level in resources:
            result = check_access(username, resource_level)
            print(f"user={username:<15} resource={resource_name:<22} -> {result}")
    print("=" * 70)
if __name__ == "__main__":
    run_task2()
