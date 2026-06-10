"""Demo data - Mocked AWS responses simulating a misconfigured environment"""


def get_iam_data() -> dict:
    return {
        "root_mfa_enabled": False,
        "root_access_keys": True,
        "password_policy": {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": False,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 0,  # Never expires
            "PasswordReusePrevention": 3,
        },
        "users_without_mfa": ["dev-intern", "jenkins-deploy", "backup-service"],
        "unused_credentials": [
            {"user": "former-employee", "days_unused": 180},
            {"user": "test-user-2023", "days_unused": 120},
            {"user": "old-cicd-bot", "days_unused": 95},
        ],
        "overpermissive_policies": [
            {"name": "DevTeamFullAccess", "actions": "*", "resources": "*"},
            {"name": "LegacyAdminPolicy", "actions": "*", "resources": "*"},
        ],
        "old_access_keys": [
            {"user": "deploy-bot", "age_days": 365},
            {"user": "monitoring-svc", "age_days": 200},
            {"user": "dev-intern", "age_days": 150},
        ],
    }


def get_s3_data() -> dict:
    return {
        "buckets": [
            {
                "name": "company-public-assets",
                "public_access": True,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "logging_enabled": False,
            },
            {
                "name": "customer-data-prod",
                "public_access": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
            },
            {
                "name": "dev-team-backups",
                "public_access": False,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "logging_enabled": False,
            },
            {
                "name": "cloudtrail-logs-2024",
                "public_access": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": False,
            },
            {
                "name": "marketing-uploads",
                "public_access": True,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "logging_enabled": False,
            },
        ]
    }


def get_ec2_data() -> dict:
    return {
        "security_groups": [
            {
                "id": "sg-0abc123def",
                "name": "web-server-sg",
                "open_rules": [
                    {"port": 22, "source": "0.0.0.0/0"},
                    {"port": 80, "source": "0.0.0.0/0"},
                    {"port": 443, "source": "0.0.0.0/0"},
                ],
            },
            {
                "id": "sg-0def456ghi",
                "name": "database-sg",
                "open_rules": [
                    {"port": 3306, "source": "0.0.0.0/0"},
                    {"port": 5432, "source": "0.0.0.0/0"},
                ],
            },
            {
                "id": "sg-0ghi789jkl",
                "name": "rdp-access-sg",
                "open_rules": [
                    {"port": 3389, "source": "0.0.0.0/0"},
                ],
            },
        ],
        "default_vpc_in_use": True,
        "unencrypted_volumes": [
            {"id": "vol-0abc123", "size_gb": 100, "instance": "i-0web001"},
            {"id": "vol-0def456", "size_gb": 500, "instance": "i-0db001"},
        ],
        "imdsv1_instances": [
            {"id": "i-0web001", "name": "web-server-1"},
            {"id": "i-0web002", "name": "web-server-2"},
            {"id": "i-0app001", "name": "app-server-1"},
        ],
        "flow_logs_enabled": False,
        "public_instances": [
            {"id": "i-0web001", "name": "web-server-1", "public_ip": "54.123.45.67"},
            {"id": "i-0bastion", "name": "bastion-host", "public_ip": "54.123.45.68"},
        ],
    }


def get_rds_data() -> dict:
    return {
        "instances": [
            {
                "identifier": "prod-mysql-primary",
                "engine": "mysql",
                "publicly_accessible": True,
                "encrypted": False,
                "multi_az": False,
                "backup_retention": 1,
                "deletion_protection": False,
            },
            {
                "identifier": "prod-postgres-analytics",
                "engine": "postgresql",
                "publicly_accessible": False,
                "encrypted": True,
                "multi_az": True,
                "backup_retention": 14,
                "deletion_protection": True,
            },
            {
                "identifier": "dev-mysql-test",
                "engine": "mysql",
                "publicly_accessible": False,
                "encrypted": False,
                "multi_az": False,
                "backup_retention": 3,
                "deletion_protection": False,
            },
        ]
    }


def get_cloudtrail_data() -> dict:
    return {
        "multi_region_enabled": False,
        "log_file_validation": False,
        "cloudwatch_logs_enabled": False,
        "kms_encryption": False,
        "s3_access_logging": False,
    }
