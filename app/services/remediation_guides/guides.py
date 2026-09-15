"""Remediation guidance per secret type.

Every guide provides:
  - immediate: things to do within the hour
  - prevention: long-term controls
  - controls: recommended tooling / patterns
  - references: OWASP / CWE / MITRE where accurate

Mappings are only included when technically correct. Do not force them.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RemediationGuide:
    secret_type: str
    immediate: tuple[str, ...]
    prevention: tuple[str, ...]
    controls: tuple[str, ...]
    references: dict[str, tuple[str, ...]] = field(default_factory=dict)


GUIDE_BY_TYPE: dict[str, RemediationGuide] = {
    "AWS Access Key": RemediationGuide(
        secret_type="AWS Access Key",
        immediate=(
            "Revoke the access key in IAM immediately.",
            "Rotate to a new key only after confirming the old one is disabled.",
            "Review CloudTrail for API calls made with the exposed key.",
            "Check attached IAM policies for privilege scope.",
            "Remove the key from source and git history.",
        ),
        prevention=(
            "Never commit long-lived keys. Use IAM roles for compute.",
            "Enable AWS CloudTrail and GuardDuty in all regions.",
            "Turn on GitHub/GitLab secret scanning with push protection.",
            "Require MFA for IAM users that still hold access keys.",
        ),
        controls=(
            "AWS Secrets Manager or SSM Parameter Store",
            "IAM Roles for EC2 / ECS / Lambda",
            "OIDC federation for CI/CD (GitHub Actions, GitLab)",
            "AWS Config rule: iam-user-no-policies-check",
        ),
        references={
            "OWASP": ("A02:2021 Cryptographic Failures", "A05:2021 Security Misconfiguration"),
            "CWE": ("CWE-798 Hard-coded Credentials", "CWE-522 Insufficiently Protected Credentials"),
            "MITRE": ("T1552.001 Credentials in Files", "T1078 Valid Accounts"),
        },
    ),
    "AWS Secret Access Key": RemediationGuide(
        secret_type="AWS Secret Access Key",
        immediate=(
            "Deactivate the associated access key ID in IAM.",
            "Rotate the secret access key.",
            "Review CloudTrail for suspicious calls.",
            "Purge from source and git history.",
        ),
        prevention=(
            "Use temporary credentials (STS) instead of long-lived keys.",
            "Store secrets in AWS Secrets Manager, never in code.",
            "Enforce secret scanning in CI.",
        ),
        controls=(
            "AWS Secrets Manager",
            "IAM Roles + STS AssumeRole",
            "GitHub/GitLab push protection",
        ),
        references={
            "OWASP": ("A02:2021 Cryptographic Failures",),
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1552.001 Credentials in Files",),
        },
    ),
    "GitHub Token": RemediationGuide(
        secret_type="GitHub Token",
        immediate=(
            "Revoke the token in GitHub Settings → Developer settings.",
            "Rotate the token if automation depends on it.",
            "Review audit log for repository and org actions.",
            "Remove from source and git history.",
        ),
        prevention=(
            "Use GitHub Actions secrets, not inline tokens.",
            "Use fine-grained PATs with the minimum scopes.",
            "Enable GitHub secret scanning and push protection.",
            "Prefer OIDC federation over long-lived PATs for CI.",
        ),
        controls=(
            "GitHub Actions Secrets",
            "GitHub OIDC to AWS/GCP/Azure",
            "Fine-grained PATs",
            "Organization-level secret scanning",
        ),
        references={
            "OWASP": ("A07:2021 Identification and Authentication Failures",),
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1552.001 Credentials in Files", "T1078 Valid Accounts"),
        },
    ),
    "Slack Token": RemediationGuide(
        secret_type="Slack Token",
        immediate=(
            "Revoke the token in the Slack app configuration.",
            "Reinstall the app and rotate credentials.",
            "Review workspace audit logs for bot activity.",
        ),
        prevention=(
            "Store tokens in a secret manager, not in code.",
            "Use the narrowest OAuth scopes possible.",
        ),
        controls=("Slack app tokens stored in AWS Secrets Manager / Vault",),
        references={
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1552.001 Credentials in Files",),
        },
    ),
    "Stripe Secret Key": RemediationGuide(
        secret_type="Stripe Secret Key",
        immediate=(
            "Roll the key in the Stripe dashboard immediately.",
            "Review recent charges, refunds, and API requests.",
            "Check for unauthorized webhook endpoints.",
        ),
        prevention=(
            "Use restricted keys per service.",
            "Store keys in a secret manager or env vars, never in code.",
            "Enable Stripe webhook signing secrets.",
        ),
        controls=("Stripe restricted keys", "AWS Secrets Manager / Vault"),
        references={
            "OWASP": ("A02:2021 Cryptographic Failures",),
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1078 Valid Accounts",),
        },
    ),
    "Private Key": RemediationGuide(
        secret_type="Private Key",
        immediate=(
            "Revoke the key everywhere it is trusted (servers, SSH configs, API providers).",
            "Generate a new key pair and redistribute the public key.",
            "Audit authorized_keys, TLS trust stores, and signing configs.",
            "Remove from source and git history.",
        ),
        prevention=(
            "Never commit private keys.",
            "Prefer short-lived certificates (e.g., SSH CA, cert-manager).",
            "Hardware-backed keys where possible.",
        ),
        controls=(
            "HashiCorp Vault / AWS KMS",
            "SSH certificates with a CA",
            "cert-manager for TLS",
        ),
        references={
            "OWASP": ("A02:2021 Cryptographic Failures",),
            "CWE": (
                "CWE-321 Use of Hard-coded Cryptographic Key",
                "CWE-798 Hard-coded Credentials",
            ),
            "MITRE": ("T1552.004 Private Keys",),
        },
    ),
    "Database Connection String": RemediationGuide(
        secret_type="Database Connection String",
        immediate=(
            "Rotate the database password.",
            "Review database logs for unusual sessions.",
            "Restrict the account to the minimum privileges required.",
        ),
        prevention=(
            "Store the connection string in a secret manager.",
            "Restrict network access with security groups / firewall rules.",
            "Require TLS for database connections.",
        ),
        controls=(
            "AWS Secrets Manager RDS rotation",
            "Vault database secrets engine",
            "IAM database authentication where supported",
        ),
        references={
            "OWASP": (
                "A02:2021 Cryptographic Failures",
                "A05:2021 Security Misconfiguration",
            ),
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1078 Valid Accounts",),
        },
    ),
    "JWT": RemediationGuide(
        secret_type="JWT",
        immediate=(
            "If the JWT carries a long-lived session, revoke the session server-side.",
            "Rotate the signing key.",
            "Check token audience and expiry.",
        ),
        prevention=(
            "Short expiry and refresh tokens.",
            "Rotate signing keys regularly (JWKS rotation).",
            "Never commit JWTs to source.",
        ),
        controls=("OIDC provider (Auth0, Cognito, Keycloak)", "JWKS rotation"),
        references={
            "OWASP": ("A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"),
            "CWE": ("CWE-522 Insufficiently Protected Credentials",),
            "MITRE": ("T1552.001 Credentials in Files",),
        },
    ),
    "Bearer Token": RemediationGuide(
        secret_type="Bearer Token",
        immediate=(
            "Revoke the token on the issuing service.",
            "Rotate the token and reissue to authorized clients.",
            "Review service logs for use of the exposed token.",
        ),
        prevention=(
            "Short token lifetimes with refresh.",
            "Store in a secret manager, never in source.",
        ),
        controls=("Issuer-side token revocation", "Secrets manager"),
        references={
            "CWE": ("CWE-522 Insufficiently Protected Credentials",),
            "MITRE": ("T1528 Steal Application Access Token",),
        },
    ),
    "Google API Key": RemediationGuide(
        secret_type="Google API Key",
        immediate=(
            "Restrict the API key in Google Cloud Console (API and referrer restrictions).",
            "Delete and recreate the key if compromised.",
            "Review Cloud Audit Logs for usage.",
        ),
        prevention=(
            "Apply API and referrer restrictions to every key.",
            "Use Workload Identity instead of long-lived keys where possible.",
        ),
        controls=("Google Secret Manager", "API restrictions", "Workload Identity"),
        references={
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1552.001 Credentials in Files",),
        },
    ),
    "API Key": RemediationGuide(
        secret_type="API Key",
        immediate=(
            "Rotate the API key with the provider.",
            "Review provider logs for unauthorized usage.",
            "Remove from source and git history.",
        ),
        prevention=(
            "Load API keys from environment variables or a secret manager.",
            "Scope keys to the minimum required permissions.",
            "Enable secret scanning on the repository host.",
        ),
        controls=("AWS Secrets Manager / Vault / Azure Key Vault", "GitHub secret scanning"),
        references={
            "OWASP": ("A05:2021 Security Misconfiguration",),
            "CWE": ("CWE-798 Hard-coded Credentials",),
            "MITRE": ("T1552.001 Credentials in Files",),
        },
    ),
    "Token": RemediationGuide(
        secret_type="Token",
        immediate=(
            "Revoke the token at the issuer.",
            "Rotate and reissue to legitimate clients.",
            "Review logs for unauthorized use.",
        ),
        prevention=(
            "Store tokens in env vars or a secret manager.",
            "Prefer short-lived tokens.",
        ),
        controls=("Secrets manager", "Short-lived tokens + refresh"),
        references={
            "CWE": ("CWE-522 Insufficiently Protected Credentials",),
            "MITRE": ("T1528 Steal Application Access Token",),
        },
    ),
    "Secret": RemediationGuide(
        secret_type="Secret",
        immediate=(
            "Rotate the secret.",
            "Review access logs for the affected service.",
            "Remove from source and git history.",
        ),
        prevention=(
            "Move secrets to a managed secret store.",
            "Enable push protection on the repository host.",
        ),
        controls=("Secrets manager", "Secret scanning"),
        references={
            "OWASP": ("A05:2021 Security Misconfiguration",),
            "CWE": ("CWE-798 Hard-coded Credentials",),
        },
    ),
    "Password": RemediationGuide(
        secret_type="Password",
        immediate=(
            "Rotate the password immediately.",
            "Check authentication logs for suspicious logins.",
            "Force logout of active sessions where applicable.",
        ),
        prevention=(
            "Never store passwords in source. Use env vars or a secret manager.",
            "Hash and salt user passwords with Argon2id or bcrypt.",
            "Enforce MFA on privileged accounts.",
        ),
        controls=(
            "AWS Secrets Manager / Vault",
            "Argon2id password hashing",
            "MFA",
        ),
        references={
            "OWASP": (
                "A02:2021 Cryptographic Failures",
                "A07:2021 Identification and Authentication Failures",
            ),
            "CWE": (
                "CWE-798 Hard-coded Credentials",
                "CWE-256 Plaintext Storage of a Password",
            ),
            "MITRE": ("T1078 Valid Accounts", "T1110 Brute Force"),
        },
    ),
}


DEFAULT_GUIDE = RemediationGuide(
    secret_type="Unknown",
    immediate=(
        "Investigate the finding manually.",
        "Rotate the credential if it is real.",
        "Remove the value from source and git history.",
    ),
    prevention=(
        "Store secrets outside source control.",
        "Enable secret scanning in the repository host.",
    ),
    controls=("A managed secret store", "Secret scanning"),
    references={
        "OWASP": ("A05:2021 Security Misconfiguration",),
        "CWE": ("CWE-798 Hard-coded Credentials",),
    },
)


def guide_for(secret_type: str) -> RemediationGuide:
    """Return the guide for a secret_type, or the default guide."""
    return GUIDE_BY_TYPE.get(secret_type, DEFAULT_GUIDE)


__all__ = ["RemediationGuide", "GUIDE_BY_TYPE", "DEFAULT_GUIDE", "guide_for"]