"""
InfraCode Test Suite
Tests for core engine, state, security, and compliance.
"""

import pytest
import json
import tempfile
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import (
    InfraEngine, TemplateParser, DependencyGraph,
    Resource, ResourceAction, ResourceStatus,
)
from core.state import StateManager
from core.plan import PlanEngine, ExecutionPlan
from core.security.scanner import SecurityScanner
from core.security.encryption import AES256GCMEncryption


# ── Template Parser Tests ────────────────────────────────────────────────

class TestTemplateParser:
    def setup_method(self):
        self.parser = TemplateParser()

    def test_parse_simple_template(self):
        yaml_content = """
name: test-template
provider: aws
version: "1.0"
resources:
  my-vpc:
    type: aws_vpc
    cidr_block: "10.0.0.0/16"
"""
        template = self.parser.parse_string(yaml_content)
        assert template.name == "test-template"
        assert template.provider == "aws"
        assert len(template.resources) == 1
        assert template.resources[0].id == "my-vpc"
        assert template.resources[0].type == "aws_vpc"

    def test_parse_with_variables(self):
        yaml_content = """
name: test
provider: aws
variables:
  env:
    type: string
    default: dev
resources:
  vpc:
    type: aws_vpc
    cidr_block: "10.0.0.0/16"
    tags:
      Environment: "${var.env}"
"""
        template = self.parser.parse_string(yaml_content)
        template = self.parser.interpolate_variables(template, {"env": "production"})
        assert template.resources[0].tags["Environment"] == "production"

    def test_parse_with_defaults(self):
        yaml_content = """
name: test
variables:
  env:
    type: string
    default: staging
resources:
  vpc:
    type: aws_vpc
    tags:
      Environment: "${var.env}"
"""
        template = self.parser.parse_string(yaml_content)
        template = self.parser.interpolate_variables(template, {})
        assert template.resources[0].tags["Environment"] == "staging"

    def test_parse_dependencies(self):
        yaml_content = """
name: test
resources:
  vpc:
    type: aws_vpc
    cidr_block: "10.0.0.0/16"
  subnet:
    type: aws_subnet
    depends_on:
      - vpc
"""
        template = self.parser.parse_string(yaml_content)
        subnet = [r for r in template.resources if r.id == "subnet"][0]
        assert "vpc" in subnet.dependencies


# ── Dependency Graph Tests ───────────────────────────────────────────────

class TestDependencyGraph:
    def test_simple_dependency(self):
        graph = DependencyGraph()
        vpc = Resource(id="vpc", type="aws_vpc", provider="aws", name="vpc")
        subnet = Resource(id="subnet", type="aws_subnet", provider="aws", name="subnet", dependencies=["vpc"])

        graph.add_resource(vpc)
        graph.add_resource(subnet)

        order = graph.get_execution_order()
        assert order.index("vpc") < order.index("subnet")

    def test_parallel_detection(self):
        graph = DependencyGraph()
        vpc = Resource(id="vpc", type="aws_vpc", provider="aws", name="vpc")
        sub1 = Resource(id="sub1", type="aws_subnet", provider="aws", name="sub1", dependencies=["vpc"])
        sub2 = Resource(id="sub2", type="aws_subnet", provider="aws", name="sub2", dependencies=["vpc"])

        graph.add_resource(vpc)
        graph.add_resource(sub1)
        graph.add_resource(sub2)

        layers = graph.topological_sort()
        assert layers[0] == ["vpc"]
        assert sorted(layers[1]) == ["sub1", "sub2"]

    def test_circular_dependency_detected(self):
        graph = DependencyGraph()
        a = Resource(id="a", type="test", provider="test", name="a", dependencies=["b"])
        b = Resource(id="b", type="test", provider="test", name="b", dependencies=["a"])

        graph.add_resource(a)
        graph.add_resource(b)

        with pytest.raises(ValueError, match="Circular dependency"):
            graph.topological_sort()


# ── Resource Tests ───────────────────────────────────────────────────────

class TestResource:
    def test_fingerprint_deterministic(self):
        r = Resource(id="test", type="aws_vpc", provider="aws", name="test", config={"cidr": "10.0.0.0/16"})
        fp1 = r.fingerprint
        fp2 = r.fingerprint
        assert fp1 == fp2

    def test_fingerprint_changes(self):
        r1 = Resource(id="test", type="aws_vpc", provider="aws", name="test", config={"cidr": "10.0.0.0/16"})
        r2 = Resource(id="test", type="aws_vpc", provider="aws", name="test", config={"cidr": "10.1.0.0/16"})
        assert r1.fingerprint != r2.fingerprint

    def test_to_dict(self):
        r = Resource(id="test", type="aws_vpc", provider="aws", name="test")
        d = r.to_dict()
        assert d["id"] == "test"
        assert d["type"] == "aws_vpc"
        assert "fingerprint" in d


# ── State Manager Tests ──────────────────────────────────────────────────

class TestStateManager:
    def test_set_and_get_resource(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = StateManager(state_dir=tmpdir)
            state.set_resource("vpc-1", {"type": "aws_vpc", "config": {"cidr": "10.0.0.0/16"}})
            resource = state.get_resource("vpc-1")
            assert resource is not None
            assert resource["type"] == "aws_vpc"

    def test_remove_resource(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = StateManager(state_dir=tmpdir)
            state.set_resource("vpc-1", {"type": "aws_vpc"})
            assert state.remove_resource("vpc-1")
            assert state.get_resource("vpc-1") is None

    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = StateManager(state_dir=tmpdir)
            state.set_resource("vpc-1", {"type": "aws_vpc", "config": {}})
            state.save()

            state2 = StateManager(state_dir=tmpdir)
            assert state2.get_resource("vpc-1") is not None

    def test_locking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = StateManager(state_dir=tmpdir)
            lock = state.acquire_lock("test-user", "apply")
            assert lock.owner == "test-user"
            state.release_lock(lock.lock_id)


# ── Security Scanner Tests ───────────────────────────────────────────────

class TestSecurityScanner:
    def setup_method(self):
        self.scanner = SecurityScanner()

    def test_detect_public_s3(self):
        findings = self.scanner.scan_config("test-bucket", "aws_s3_bucket", {"acl": "public-read"})
        assert any(f.rule_id == "SEC001" for f in findings)

    def test_detect_unencrypted_s3(self):
        findings = self.scanner.scan_config("test-bucket", "aws_s3_bucket", {"acl": "private"})
        assert any(f.rule_id == "SEC002" for f in findings)

    def test_secure_config_passes(self):
        findings = self.scanner.scan_config("good-bucket", "aws_s3_bucket", {
            "acl": "private",
            "encryption": {"sse_algorithm": "AES256"},
            "public_access_block": True,
        })
        critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH") and f.rule_id.startswith("SEC00")]
        sec001 = [f for f in critical if f.rule_id == "SEC001"]
        sec002 = [f for f in critical if f.rule_id == "SEC002"]
        assert len(sec001) == 0
        assert len(sec002) == 0

    def test_report_generation(self):
        findings = self.scanner.scan_config("bad-bucket", "aws_s3_bucket", {"acl": "public-read"})
        report = self.scanner.generate_report(findings)
        assert "total_findings" in report
        assert "score" in report


# ── Encryption Tests ─────────────────────────────────────────────────────

class TestEncryption:
    def test_encrypt_decrypt(self):
        enc = AES256GCMEncryption("test-passphrase-for-testing")
        plaintext = "Hello, InfraCode!"
        ciphertext = enc.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = enc.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_generate_key(self):
        key = AES256GCMEncryption.generate_key()
        assert len(key) > 0

    def test_different_keys_different_output(self):
        enc1 = AES256GCMEncryption("key-one")
        enc2 = AES256GCMEncryption("key-two")
        ct1 = enc1.encrypt("test")
        ct2 = enc2.encrypt("test")
        assert ct1 != ct2


# ── Plan Engine Tests ────────────────────────────────────────────────────

class TestPlanEngine:
    def test_create_plan(self):
        pe = PlanEngine()
        resources = [
            Resource(id="vpc", type="aws_vpc", provider="aws", name="vpc", config={"cidr": "10.0.0.0/16"}),
        ]
        plan = pe.generate_plan(resources, {}, "test")
        assert plan.summary["create"] == 1

    def test_noop_plan(self):
        pe = PlanEngine()
        r = Resource(id="vpc", type="aws_vpc", provider="aws", name="vpc", config={"cidr": "10.0.0.0/16"})
        current = {"vpc": {"config": {"cidr": "10.0.0.0/16"}, "type": "aws_vpc", "fingerprint": r.fingerprint}}
        plan = pe.generate_plan([r], current, "test")
        assert plan.summary["noop"] == 1

    def test_format_text(self):
        pe = PlanEngine()
        resources = [Resource(id="vpc", type="aws_vpc", provider="aws", name="vpc", config={"cidr": "10.0.0.0/16"})]
        plan = pe.generate_plan(resources, {}, "test")
        text = plan.format_text()
        assert "InfraCode" in text
        assert "CREATE" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
