"""Tests for probe modules and engine using simulated data.

These tests validate the probe simulation mode, scoring engine logic,
and steganography encode/decode round-trip without requiring network access.
"""

import unittest
import json
import os

from scanner.probes.tcp_probe import TCPProbe, TCPProbeResult
from scanner.probes.http_probe import HTTPProbe, HTTPProbeResult
from scanner.probes.dns_probe import DNSProbe, DNSProbeResult
from scanner.probes.icmp_probe import ICMPProbe, ICMPProbeResult
from scanner.probes.dpi_probe import DPIProbe, DPIProbeResult
from scanner.engine.scorer import TechniqueScorer, TechniqueID
from scanner.engine.recommender import Recommender
from scanner.generators.ssh_config import SSHConfigGenerator
from scanner.generators.stunnel import StunnelGenerator
from scanner.generators.wstunnel import WstunnelGenerator
from scanner.generators.sslh import SSLHGenerator
from scanner.generators.tor import TorGenerator
from scanner.stego.http_stego import StegoEncoder, StegoDecoder


class TestTCPProbe(unittest.TestCase):
    """Test TCP probe simulation."""

    def test_simulate_returns_results(self):
        probe = TCPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIsInstance(result, TCPProbeResult)
        self.assertEqual(result.target_ip, "203.0.113.50")
        self.assertGreater(len(result.ports), 0)

    def test_simulate_has_open_ports(self):
        probe = TCPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIn(80, result.open_ports)
        self.assertIn(443, result.open_ports)
        self.assertIn(22, result.filtered_ports)

    def test_simulate_port_details(self):
        probe = TCPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        port80 = result.ports[80]
        self.assertEqual(port80.state, "open")
        self.assertEqual(port80.service, "HTTP")
        self.assertGreater(port80.latency_ms, 0)


class TestHTTPProbe(unittest.TestCase):
    """Test HTTP probe simulation."""

    def test_simulate_returns_results(self):
        probe = HTTPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIsInstance(result, HTTPProbeResult)
        self.assertFalse(result.proxy_detected)
        self.assertFalse(result.tls_intercept)

    def test_simulate_tls_issuer(self):
        probe = HTTPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertEqual(result.tls_issuer, "Let's Encrypt")


class TestDNSProbe(unittest.TestCase):
    """Test DNS probe simulation."""

    def test_simulate_returns_results(self):
        probe = DNSProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIsInstance(result, DNSProbeResult)
        self.assertTrue(result.dns_open)
        self.assertFalse(result.dns_manipulated)

    def test_simulate_tunnel_viable(self):
        probe = DNSProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertTrue(result.tunnel_viable)
        self.assertGreater(result.estimated_bandwidth_kbps, 0)


class TestICMPProbe(unittest.TestCase):
    """Test ICMP probe simulation."""

    def test_simulate_returns_results(self):
        probe = ICMPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIsInstance(result, ICMPProbeResult)
        self.assertTrue(result.icmp_allowed)

    def test_simulate_latency(self):
        probe = ICMPProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertGreater(result.avg_latency_ms, 0)
        self.assertEqual(result.packet_loss_pct, 0.0)


class TestDPIProbe(unittest.TestCase):
    """Test DPI probe simulation."""

    def test_simulate_returns_results(self):
        probe = DPIProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertIsInstance(result, DPIProbeResult)
        self.assertTrue(result.dpi_detected)
        self.assertTrue(result.ssh_banner_blocked)

    def test_simulate_has_test_results(self):
        probe = DPIProbe("203.0.113.50")
        result = probe.run(simulate=True)
        self.assertGreater(len(result.tests_performed), 0)
        self.assertGreater(len(result.test_results), 0)


class TestScorer(unittest.TestCase):
    """Test technique scoring engine."""

    def setUp(self):
        """Set up probe results from simulation."""
        self.tcp = TCPProbe("203.0.113.50").run(simulate=True)
        self.http = HTTPProbe("203.0.113.50").run(simulate=True)
        self.dns = DNSProbe("203.0.113.50").run(simulate=True)
        self.icmp = ICMPProbe("203.0.113.50").run(simulate=True)
        self.dpi = DPIProbe("203.0.113.50").run(simulate=True)

        self.probes = {
            "tcp": self.tcp,
            "http": self.http,
            "dns": self.dns,
            "icmp": self.icmp,
            "dpi": self.dpi,
        }

    def test_score_all_returns_list(self):
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        self.assertIsInstance(scores, list)
        self.assertGreater(len(scores), 0)

    def test_scores_are_sorted(self):
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        # Available techniques should come first
        available = [s for s in scores if not s.blocked and not s.not_tested]
        for i in range(len(available) - 1):
            self.assertGreaterEqual(available[i].score, available[i + 1].score)

    def test_direct_ssh_blocked_when_filtered(self):
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        direct = next(s for s in scores
                      if s.technique == TechniqueID.DIRECT_SSH)
        self.assertTrue(direct.blocked)

    def test_obfs4_scores_high_with_dpi(self):
        """With DPI detected, obfs4 should score high."""
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        obfs4 = next(s for s in scores
                     if s.technique == TechniqueID.OBFS4)
        self.assertFalse(obfs4.blocked)
        self.assertGreater(obfs4.score, 7.0)

    def test_dns_tunnel_available(self):
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        dns = next(s for s in scores
                   if s.technique == TechniqueID.DNS_TUNNEL)
        self.assertFalse(dns.blocked)
        self.assertGreater(dns.score, 0)

    def test_all_techniques_have_justification(self):
        scorer = TechniqueScorer()
        scores = scorer.score_all(self.probes)
        for score in scores:
            self.assertTrue(
                score.justification,
                f"{score.technique} has no justification"
            )


class TestRecommender(unittest.TestCase):
    """Test the full recommendation pipeline."""

    def test_simulate_assessment(self):
        rec = Recommender("203.0.113.50", domain="covert.example.com")
        assessment = rec.assess(simulate=True)
        self.assertIsNotNone(assessment.tcp)
        self.assertIsNotNone(assessment.http)
        self.assertIsNotNone(assessment.dns)
        self.assertIsNotNone(assessment.scores)
        self.assertIsNotNone(assessment.best_technique)

    def test_dry_run(self):
        rec = Recommender("203.0.113.50")
        assessment = rec.assess(dry_run=True)
        self.assertGreater(len(assessment.errors), 0)
        self.assertTrue(all("[DRY-RUN]" in e for e in assessment.errors))

    def test_best_technique_is_viable(self):
        rec = Recommender("203.0.113.50")
        assessment = rec.assess(simulate=True)
        best = assessment.best_technique
        self.assertIsNotNone(best)
        self.assertFalse(best.blocked)
        self.assertFalse(best.not_tested)
        self.assertGreater(best.score, 0)


class TestGenerators(unittest.TestCase):
    """Test configuration generators."""

    def test_stunnel_generator(self):
        gen = StunnelGenerator("203.0.113.50", user="testuser")
        config = gen.generate()
        self.assertIn("stunnel", config.server_conf.lower())
        self.assertIn("203.0.113.50", config.client_conf)
        self.assertIn("ssh", config.ssh_command.lower())

    def test_wstunnel_generator(self):
        gen = WstunnelGenerator("203.0.113.50", "covert.example.com",
                                user="testuser")
        config = gen.generate()
        self.assertIn("wstunnel", config.server_command)
        self.assertIn("covert.example.com", config.nginx_conf)

    def test_sslh_generator(self):
        gen = SSLHGenerator("203.0.113.50", user="testuser")
        config = gen.generate()
        self.assertIn("ssh", config.config_file.lower())
        self.assertIn("443", config.ssh_command)

    def test_tor_generator(self):
        gen = TorGenerator("203.0.113.50", user="testuser")
        config = gen.generate()
        self.assertIn("HiddenService", config.torrc)
        self.assertIn("onion", config.ssh_command)

    def test_ssh_config_all_techniques(self):
        gen = SSHConfigGenerator("203.0.113.50", "covert.example.com",
                                 user="testuser")
        for technique in TechniqueID:
            config = gen.generate(technique)
            self.assertTrue(config.config_entry)
            self.assertTrue(config.description)
            self.assertTrue(config.direct_command)

    def test_stunnel_docker_compose(self):
        gen = StunnelGenerator("203.0.113.50")
        compose = gen.generate_docker_compose()
        self.assertIn("services:", compose)
        self.assertIn("sslh:", compose)

    def test_wstunnel_docker_compose(self):
        gen = WstunnelGenerator("203.0.113.50")
        compose = gen.generate_docker_compose()
        self.assertIn("services:", compose)
        self.assertIn("wstunnel:", compose)


class TestSteganography(unittest.TestCase):
    """Test HTTP steganography encode/decode round-trip."""

    def setUp(self):
        self.key = "test-secret-key"
        self.encoder = StegoEncoder(self.key)
        self.decoder = StegoDecoder(self.key)

    def test_json_body_roundtrip(self):
        """Test encoding/decoding through JSON body."""
        data = b"SSH-2.0-OpenSSH_8.9\r\n"
        encoded = self.encoder.encode_to_json_body(data)
        decoded = self.decoder.decode_from_json_body(encoded)
        self.assertEqual(decoded, data)

    def test_json_body_is_valid_json(self):
        data = b"test data 12345"
        encoded = self.encoder.encode_to_json_body(data)
        parsed = json.loads(encoded)
        self.assertIn("events", parsed)
        self.assertIn("client_id", parsed)

    def test_large_payload_roundtrip(self):
        """Test with larger payload."""
        data = os.urandom(512)
        encoded = self.encoder.encode_to_json_body(data)
        decoded = self.decoder.decode_from_json_body(encoded)
        self.assertEqual(decoded, data)

    def test_build_request_get(self):
        data = b"small data"
        req = self.encoder.build_request(data, method="GET")
        self.assertEqual(req["method"], "GET")
        self.assertIn("?", req["path"])
        self.assertIn("User-Agent", req["headers"])

    def test_build_request_post(self):
        data = b"x" * 200
        req = self.encoder.build_request(data, method="POST")
        self.assertEqual(req["method"], "POST")
        self.assertIsNotNone(req["body"])
        self.assertIn("Content-Type", req["headers"])

    def test_full_request_roundtrip_post(self):
        """Test full request encode/decode cycle for POST."""
        data = b"SSH-2.0-OpenSSH_8.9\r\nsome more data here"
        req = self.encoder.build_request(data, method="POST")
        decoded = self.decoder.decode_request(
            req["method"], req["path"], req["headers"], req["body"]
        )
        self.assertEqual(decoded, data)

    def test_wrong_key_fails(self):
        """Data encoded with one key should not decode with another."""
        data = b"secret data"
        encoded = self.encoder.encode_to_json_body(data)
        wrong_decoder = StegoDecoder("wrong-key")
        decoded = wrong_decoder.decode_from_json_body(encoded)
        # Should decode the bytes but they'll be garbled
        if decoded is not None:
            self.assertNotEqual(decoded, data)

    def test_non_stego_request_returns_none(self):
        """Non-steganographic request should return None."""
        decoded = self.decoder.decode_request(
            "GET", "/index.html", {"User-Agent": "Mozilla"}, None
        )
        self.assertIsNone(decoded)

    def test_cookie_encoding_produces_known_names(self):
        data = b"test"
        cookies = self.encoder.encode_to_cookie(data)
        # Should use known cookie names
        for name in cookies:
            self.assertIn(name, [
                "_ga", "_gid", "_fbp", "session_id", "csrf_token",
                "prefs", "lang", "theme", "__cfduid",
            ])


if __name__ == "__main__":
    unittest.main()
