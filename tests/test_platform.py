"""
Test suite for Bug Bounty Platform.
Tests cover service logic, API endpoints, and model behavior.
All tests use mocked external tool calls — no real network activity.
"""
import json
import pytest
from unittest.mock import MagicMock, patch

# ─── Service Tests ─────────────────────────────────────────────────────────────

class TestAnalysisService:
    """Tests for finding normalization and attack path analysis."""

    def test_categorize_xss(self):
        from app.services.analysis_service import _categorize_finding
        from app.models.models import FindingCategory
        assert _categorize_finding("xss-reflected", "Reflected XSS") == FindingCategory.XSS

    def test_categorize_sqli(self):
        from app.services.analysis_service import _categorize_finding
        from app.models.models import FindingCategory
        assert _categorize_finding("sqli-time-based", "Time-based SQL Injection") == FindingCategory.SQLI

    def test_categorize_ssrf(self):
        from app.services.analysis_service import _categorize_finding
        from app.models.models import FindingCategory
        assert _categorize_finding("ssrf-internal-ip", "SSRF via URL parameter") == FindingCategory.SSRF

    def test_categorize_fallback(self):
        from app.services.analysis_service import _categorize_finding
        from app.models.models import FindingCategory
        assert _categorize_finding("unknown-template", "Unknown Issue") == FindingCategory.OTHER

    def test_normalize_nuclei_empty(self):
        from app.services.analysis_service import normalize_nuclei_findings
        assert normalize_nuclei_findings([]) == []

    def test_normalize_nuclei_finding(self):
        from app.services.analysis_service import normalize_nuclei_findings
        from app.services.recon_service import NucleiResult
        from app.models.models import FindingSeverity, FindingCategory

        nr = NucleiResult(
            template_id="xss-reflected",
            name="Reflected XSS",
            severity="high",
            url="https://example.com",
            matched_at="https://example.com?q=test",
            description="XSS in query parameter",
            request="GET /?q=test HTTP/1.1",
            response="<script>alert</script>",
            raw={"info": {"severity": "high"}},
        )
        results = normalize_nuclei_findings([nr])
        assert len(results) == 1
        assert results[0].category == FindingCategory.XSS
        assert results[0].severity == FindingSeverity.HIGH
        assert results[0].parameter == "q"

    def test_attack_path_xss(self):
        from app.services.analysis_service import (
            analyze_finding_relationships, NormalizedFinding
        )
        from app.models.models import FindingCategory, FindingSeverity

        findings = [
            NormalizedFinding(
                title="Reflected XSS",
                description="XSS in search param",
                category=FindingCategory.XSS,
                severity=FindingSeverity.HIGH,
                url="https://example.com/search?q=test",
            )
        ]
        paths = analyze_finding_relationships(findings)
        assert any("XSS" in p.title for p in paths)
        assert all(0.0 <= p.confidence <= 1.0 for p in paths)

    def test_attack_path_sqli_sensitive_data_increases_confidence(self):
        from app.services.analysis_service import (
            analyze_finding_relationships, NormalizedFinding
        )
        from app.models.models import FindingCategory, FindingSeverity

        findings_without = [
            NormalizedFinding("SQLi", "desc", FindingCategory.SQLI, FindingSeverity.HIGH, "https://example.com")
        ]
        findings_with = findings_without + [
            NormalizedFinding("Secrets", "desc", FindingCategory.SENSITIVE_DATA, FindingSeverity.MEDIUM, "https://example.com/secrets")
        ]

        paths_without = analyze_finding_relationships(findings_without)
        paths_with = analyze_finding_relationships(findings_with)

        sqli_path_without = next((p for p in paths_without if "SQL" in p.title), None)
        sqli_path_with = next((p for p in paths_with if "SQL" in p.title), None)

        assert sqli_path_without and sqli_path_with
        assert sqli_path_with.confidence > sqli_path_without.confidence

    def test_summarize_findings(self):
        from app.services.analysis_service import summarize_findings, NormalizedFinding
        from app.models.models import FindingCategory, FindingSeverity

        findings = [
            NormalizedFinding("X", "d", FindingCategory.XSS, FindingSeverity.HIGH, "http://a.com"),
            NormalizedFinding("Y", "d", FindingCategory.SQLI, FindingSeverity.CRITICAL, "http://b.com"),
            NormalizedFinding("Z", "d", FindingCategory.XSS, FindingSeverity.MEDIUM, "http://c.com"),
        ]
        summary = summarize_findings(findings)
        assert summary["total"] == 3
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_category"]["xss"] == 2
        assert summary["by_category"]["sqli"] == 1


class TestValidationService:
    """Tests for suggested validation command generation."""

    def test_xss_commands_include_dalfox(self):
        from app.services.validation_service import generate_validation_suggestions
        from app.models.models import FindingCategory, FindingSeverity

        suggestion = generate_validation_suggestions(
            finding_id="test-id",
            title="Reflected XSS",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.XSS,
            url="https://example.com/search",
            parameter="q",
        )
        combined = " ".join(suggestion.commands)
        assert "dalfox" in combined
        assert "https://example.com/search" in combined

    def test_rce_has_risk_note(self):
        from app.services.validation_service import generate_validation_suggestions
        from app.models.models import FindingCategory, FindingSeverity

        suggestion = generate_validation_suggestions(
            finding_id="test-id",
            title="RCE via cmd param",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.RCE,
            url="https://example.com/exec",
        )
        assert suggestion.risk_note != ""

    def test_sqli_commands_use_safe_sqlmap(self):
        from app.services.validation_service import generate_validation_suggestions
        from app.models.models import FindingCategory, FindingSeverity

        suggestion = generate_validation_suggestions(
            finding_id="test-id",
            title="SQL Injection",
            severity=FindingSeverity.HIGH,
            category=FindingCategory.SQLI,
            url="https://example.com/user",
            parameter="id",
        )
        combined = " ".join(suggestion.commands)
        assert "sqlmap" in combined
        assert "--risk=1" in combined
        assert "--level=1" in combined

    def test_bulk_report_is_markdown(self):
        from app.services.validation_service import (
            generate_bulk_validation_report, ValidationSuggestion
        )
        suggestions = [
            ValidationSuggestion(
                finding_id="1", title="Test", severity="high", category="xss",
                url="https://example.com", commands=["curl test"], notes="note"
            )
        ]
        report = generate_bulk_validation_report(suggestions)
        assert "# Analyst Validation Guide" in report
        assert "```bash" in report


class TestShellUtils:
    """Tests for shell command execution utilities."""

    def test_run_command_success(self):
        from app.utils.shell import run_command
        result = run_command(["echo", "hello"])
        assert result.success
        assert "hello" in result.stdout

    def test_run_command_not_found(self):
        from app.utils.shell import run_command
        result = run_command(["this_tool_definitely_does_not_exist_xyz123"])
        assert not result.success
        assert result.returncode == 127

    def test_run_command_timeout(self):
        from app.utils.shell import run_command
        result = run_command(["sleep", "10"], timeout=1)
        assert result.timed_out

    def test_command_result_lines(self):
        from app.utils.shell import run_command
        result = run_command(["printf", "a\nb\nc\n"])
        assert result.lines() == ["a", "b", "c"]

    def test_check_tool_available_echo(self):
        from app.utils.shell import check_tool_available
        assert check_tool_available("echo")

    def test_check_tool_available_missing(self):
        from app.utils.shell import check_tool_available
        assert not check_tool_available("nonexistent_tool_abc123")


class TestReconService:
    """Tests for recon service (mocked tool execution)."""

    @patch("app.services.recon_service.run_command")
    def test_subdomain_enum_includes_root(self, mock_run):
        from app.services.recon_service import subdomain_enum
        # Simulate both tools returning empty / failing
        mock_run.return_value = MagicMock(success=False, stdout="", stderr="", lines=lambda: [])
        results = subdomain_enum("example.com")
        assert any(r.subdomain == "example.com" for r in results)

    @patch("app.services.recon_service.run_command")
    def test_subdomain_enum_deduplicates(self, mock_run):
        from app.services.recon_service import subdomain_enum
        # Both tools return the same subdomain
        mock_run.return_value = MagicMock(
            success=True,
            stdout="sub.example.com\nsub.example.com\n",
            stderr="",
            lines=lambda: ["sub.example.com", "sub.example.com"],
        )
        results = subdomain_enum("example.com")
        values = [r.subdomain for r in results]
        assert values.count("sub.example.com") == 1

    @patch("app.services.recon_service.run_command")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_probe_alive_empty(self, mock_unlink, mock_tmpfile, mock_run):
        from app.services.recon_service import probe_alive
        result = probe_alive([])
        assert result == []
        mock_run.assert_not_called()

    @patch("app.services.recon_service.run_command")
    def test_scan_vulnerabilities_empty(self, mock_run):
        from app.services.recon_service import scan_vulnerabilities
        result = scan_vulnerabilities([])
        assert result == []
        mock_run.assert_not_called()


class TestSchemas:
    """Tests for Pydantic schema validation."""

    def test_target_create_cleans_domain(self):
        from app.schemas.schemas import TargetCreate
        t = TargetCreate(domain="  https://EXAMPLE.COM/  ")
        assert t.domain == "example.com"

    def test_target_create_rejects_short_domain(self):
        from app.schemas.schemas import TargetCreate
        with pytest.raises(Exception):
            TargetCreate(domain="a")

    def test_scan_options_defaults(self):
        from app.schemas.schemas import ScanOptions
        opts = ScanOptions()
        assert opts.run_ffuf is False
        assert opts.run_gowitness is True
        assert opts.timeout == 3600

    def test_scan_create(self):
        from app.schemas.schemas import ScanCreate
        sc = ScanCreate(domain="example.com")
        assert sc.domain == "example.com"
        assert sc.options.nuclei_severity == "low,medium,high,critical"


class TestConfig:
    """Tests for settings configuration."""

    def test_database_url_format(self):
        from app.config import Settings
        s = Settings(
            postgres_host="db", postgres_port=5432,
            postgres_db="test", postgres_user="user", postgres_password="pass"
        )
        assert "asyncpg" in s.database_url
        assert "db:5432" in s.database_url

    def test_sync_database_url_format(self):
        from app.config import Settings
        s = Settings(postgres_host="db", postgres_user="u", postgres_password="p", postgres_db="d")
        assert "postgresql://" in s.sync_database_url
        assert "asyncpg" not in s.sync_database_url

    def test_allowed_telegram_users_parsing(self):
        from app.config import Settings
        s = Settings(telegram_allowed_users="123456789,987654321")
        assert s.allowed_telegram_users == [123456789, 987654321]

    def test_allowed_telegram_users_empty(self):
        from app.config import Settings
        s = Settings(telegram_allowed_users="")
        assert s.allowed_telegram_users == []
