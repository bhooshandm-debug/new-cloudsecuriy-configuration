from datetime import datetime, timezone
from flask import Blueprint, Response, current_app, render_template, request, url_for

bp = Blueprint("seo", __name__)


@bp.route("/robots.txt", methods=["GET"])
def robots_txt():
    domain = current_app.config.get("CANONICAL_URL_BASE", "https://cloudsec.io").rstrip("/")
    content = f"""# CloudSec Production Robots Policy
User-agent: *
Allow: /login
Allow: /register
Allow: /forgot-password
Allow: /llms.txt
Allow: /sitemap.xml
Disallow: /dashboard/
Disallow: /accounts/
Disallow: /scans/
Disallow: /findings/
Disallow: /reports/
Disallow: /assistant/
Disallow: /admin/
Disallow: /reset-password/

# Canonical Sitemap Reference
Sitemap: {domain}/sitemap.xml
"""
    return Response(content.strip(), mimetype="text/plain")


@bp.route("/sitemap.xml", methods=["GET"])
def sitemap_xml():
    base = current_app.config.get("CANONICAL_URL_BASE", "https://cloudsec.io").rstrip("/")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Only public, crawlable endpoints should be included in the sitemap
    pages = [
        {"loc": f"{base}/login", "changefreq": "monthly", "priority": "1.0", "lastmod": now},
        {"loc": f"{base}/register", "changefreq": "monthly", "priority": "0.8", "lastmod": now},
        {"loc": f"{base}/forgot-password", "changefreq": "yearly", "priority": "0.3", "lastmod": now},
        {"loc": f"{base}/llms.txt", "changefreq": "weekly", "priority": "0.7", "lastmod": now},
    ]

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for page in pages:
        xml_lines.append("  <url>")
        xml_lines.append(f"    <loc>{page['loc']}</loc>")
        xml_lines.append(f"    <lastmod>{page['lastmod']}</lastmod>")
        xml_lines.append(f"    <changefreq>{page['changefreq']}</changefreq>")
        xml_lines.append(f"    <priority>{page['priority']}</priority>")
        xml_lines.append("  </url>")
    xml_lines.append("</urlset>")

    return Response("\n".join(xml_lines), mimetype="application/xml")


@bp.route("/llms.txt", methods=["GET"])
def llms_txt():
    domain = current_app.config.get("CANONICAL_URL_BASE", "https://cloudsec.io").rstrip("/")
    content = f"""# CloudSec — Enterprise Cloud Security Configuration & Audit Platform
> Production-grade, read-only multi-cloud security assessment and compliance audit system for Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).

## Overview
CloudSec ({domain}) provides automated, zero-trust cloud configuration audits against industry-standard benchmarks including CIS (Center for Internet Security), NIST SP 800-53, and ISO/IEC 27001.

## Supported Cloud Providers
- Amazon Web Services (AWS): IAM policies, S3 bucket encryption & public access, RDS security, CloudTrail logging, KMS key rotation, VPC security groups.
- Microsoft Azure: Entra ID (Azure AD) MFA, Storage Account public access, Key Vault access policies, Network Security Groups, SQL audit settings.
- Google Cloud Platform (GCP): Service account permissions, Cloud Storage IAM & bucket-level access, Compute Engine firewall rules, Cloud KMS encryption.

## Security Architecture & Data Protection
- Zero-Trust Read-Only: CloudSec strictly requires read-only / SecurityAudit permissions. No mutate, delete, or provisioning actions are ever requested or performed.
- Cryptographic Storage: All cloud credentials and access keys are encrypted at rest using authenticated Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
- STS Live Verification: AWS STS and cloud IAM endpoints verify credentials server-side prior to registration. Credentials are never sent to the client browser or included in audit logs.
- AI Remediation Assistant: Gemini-assisted security explanations and CLI/IaC remediation guidance (Terraform, CloudFormation, Azure CLI) processed with strict privacy controls. Cloud credentials are never transmitted to AI models.

## Application Endpoints
- Public Authentication:
  - {domain}/login : Secure user authentication
  - {domain}/register : Auditor account registration
  - {domain}/forgot-password : Timed token password recovery
- Authenticated Audit Console:
  - {domain}/ : Security posture dashboard & aggregate metrics
  - {domain}/accounts/ : Multi-cloud inventory & credential management
  - {domain}/scans/ : Audit execution, baseline scans, and history
  - {domain}/scans/compare : Posture drift & scan delta comparison
  - {domain}/findings/ : Actionable vulnerability findings & remediation
  - {domain}/reports/ : Compliance export in HTML, CSV, and JSON formats
  - {domain}/assistant/ : Gemini AI cloud security copilot
"""
    return Response(content.strip(), mimetype="text/plain; charset=utf-8")
