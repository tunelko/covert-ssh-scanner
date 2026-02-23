"""Recommendation engine that orchestrates probes and generates reports.

Combines probe results with the scoring engine to produce actionable
recommendations with justifications.
"""

from dataclasses import dataclass, field

from scanner.probes.tcp_probe import TCPProbe, TCPProbeResult
from scanner.probes.http_probe import HTTPProbe, HTTPProbeResult
from scanner.probes.dns_probe import DNSProbe, DNSProbeResult
from scanner.probes.icmp_probe import ICMPProbe, ICMPProbeResult
from scanner.probes.dpi_probe import DPIProbe, DPIProbeResult
from scanner.engine.scorer import TechniqueScorer, TechniqueScore


@dataclass
class NetworkAssessment:
    """Complete network assessment with probe results and recommendations."""

    target: str
    domain: str
    source_ip: str = ""
    tcp: TCPProbeResult | None = None
    http: HTTPProbeResult | None = None
    dns: DNSProbeResult | None = None
    icmp: ICMPProbeResult | None = None
    dpi: DPIProbeResult | None = None
    scores: list[TechniqueScore] = field(default_factory=list)
    best_technique: TechniqueScore | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def probe_results(self) -> dict:
        """Return probe results as a dictionary for the scorer."""
        return {
            "tcp": self.tcp,
            "http": self.http,
            "dns": self.dns,
            "icmp": self.icmp,
            "dpi": self.dpi,
        }


class Recommender:
    """Orchestrates network probes and generates technique recommendations.

    Runs probes in sequence, feeds results to the scoring engine, and
    produces a ranked list of recommendations.
    """

    def __init__(self, target: str, domain: str | None = None,
                 timeout: float = 5.0, full_scan: bool = False):
        self.target = target
        self.domain = domain or target
        self.timeout = timeout
        self.full_scan = full_scan
        self.scorer = TechniqueScorer()

    def assess(self, simulate: bool = False,
               dry_run: bool = False) -> NetworkAssessment:
        """Run full network assessment.

        Args:
            simulate: Use simulated probe data (for demo/testing).
            dry_run: Show what probes would run without executing them.

        Returns:
            NetworkAssessment with all results and recommendations.
        """
        assessment = NetworkAssessment(
            target=self.target,
            domain=self.domain,
        )

        if dry_run:
            return self._dry_run(assessment)

        # Phase 1: Basic probes (no root required)
        assessment.tcp = self._run_tcp_probe(simulate)
        assessment.source_ip = assessment.tcp.source_ip if assessment.tcp else ""

        assessment.http = self._run_http_probe(simulate)
        assessment.dns = self._run_dns_probe(simulate)

        # Phase 2: Privileged probes (root required, --full mode)
        if self.full_scan:
            assessment.icmp = self._run_icmp_probe(simulate)
            assessment.dpi = self._run_dpi_probe(simulate)
        else:
            # Still attempt DPI detection without root (uses TCP sockets)
            assessment.dpi = self._run_dpi_probe(simulate)

        # Phase 3: Score and rank techniques
        assessment.scores = self.scorer.score_all(assessment.probe_results)

        # Find best available technique
        for score in assessment.scores:
            if not score.blocked and not score.not_tested:
                assessment.best_technique = score
                break

        return assessment

    def _run_tcp_probe(self, simulate: bool) -> TCPProbeResult | None:
        """Execute TCP port probe."""
        try:
            probe = TCPProbe(self.target, timeout=self.timeout)
            return probe.run(simulate=simulate)
        except Exception as e:
            return None

    def _run_http_probe(self, simulate: bool) -> HTTPProbeResult | None:
        """Execute HTTP/TLS probe."""
        try:
            probe = HTTPProbe(self.target, domain=self.domain,
                              timeout=self.timeout)
            return probe.run(simulate=simulate)
        except Exception as e:
            return None

    def _run_dns_probe(self, simulate: bool) -> DNSProbeResult | None:
        """Execute DNS probe."""
        try:
            probe = DNSProbe(self.target, domain=self.domain,
                             timeout=self.timeout)
            return probe.run(simulate=simulate)
        except Exception as e:
            return None

    def _run_icmp_probe(self, simulate: bool) -> ICMPProbeResult | None:
        """Execute ICMP probe (requires root)."""
        try:
            probe = ICMPProbe(self.target, timeout=self.timeout)
            return probe.run(simulate=simulate)
        except Exception as e:
            return None

    def _run_dpi_probe(self, simulate: bool) -> DPIProbeResult | None:
        """Execute DPI detection probe."""
        try:
            probe = DPIProbe(self.target, timeout=self.timeout)
            return probe.run(simulate=simulate)
        except Exception as e:
            return None

    def _dry_run(self, assessment: NetworkAssessment) -> NetworkAssessment:
        """Show what probes would be run without executing them."""
        probes_planned = [
            f"TCP port scan: {self.target} ports 22,80,443,53,8443,8080,993,995,587",
            f"HTTP proxy detection: {self.target} (CONNECT + transparent proxy)",
            f"TLS interception check: {self.target}:443",
            f"DNS resolution comparison: {self.domain} (system vs public DNS)",
            f"NXDOMAIN hijack check: random nonexistent domain",
        ]
        if self.full_scan:
            probes_planned.extend([
                f"ICMP echo: {self.target} (5 pings, variable payload sizes)",
                f"DPI detection: SSH banner on :80/:443, SSH-in-TLS, protocol enforcement",
            ])
        else:
            probes_planned.append(
                f"DPI detection (basic): SSH banner on :80/:443"
            )

        assessment.errors = [f"[DRY-RUN] Would execute: {p}" for p in probes_planned]
        return assessment
