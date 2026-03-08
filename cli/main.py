"""
InfraCode CLI
Command-line interface for infrastructure management.

Usage:
    python -m cli.main init <project_name>
    python -m cli.main validate <template>
    python -m cli.main plan --config <template>
    python -m cli.main apply --config <template> [--auto-approve]
    python -m cli.main destroy --config <template> [--auto-approve]
    python -m cli.main state list
    python -m cli.main state rollback <serial>
    python -m cli.main history
    python -m cli.main scan <template>
    python -m cli.main compliance --policy <policy_file> --config <template>
    python -m cli.main vault set <key> <value>
    python -m cli.main vault get <key>
    python -m cli.main version
"""

import sys
import os
import json
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import __version__
from core.engine import InfraEngine
from core.state import StateManager
from core.plan import PlanEngine
from core.security.scanner import SecurityScanner
from core.security.compliance import ComplianceEngine
from core.security.vault import SecretVault
from core.versioning.version_control import VersionControl, GitIntegration


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("infracode.cli")


BANNER = r"""
╔══════════════════════════════════════════════════════╗
║                                                      ║
║     ██╗███╗   ██╗███████╗██████╗  █████╗             ║
║     ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗            ║
║     ██║██╔██╗ ██║█████╗  ██████╔╝███████║            ║
║     ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║            ║
║     ██║██║ ╚████║██║     ██║  ██║██║  ██║            ║
║     ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝            ║
║              ██████╗ ██████╗ ██████╗ ███████╗         ║
║             ██╔════╝██╔═══██╗██╔══██╗██╔════╝        ║
║             ██║     ██║   ██║██║  ██║█████╗          ║
║             ██║     ██║   ██║██║  ██║██╔══╝          ║
║             ╚██████╗╚██████╔╝██████╔╝███████╗        ║
║              ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝        ║
║                                                      ║
║     Infrastructure as Code Platform v{version}        ║
║     By Ali AlEnezi (@SiteQ8)                         ║
╚══════════════════════════════════════════════════════╝
""".format(version=__version__)


def cmd_init(args):
    """Initialize a new InfraCode project."""
    project_name = args.name
    project_dir = Path(project_name)

    if project_dir.exists():
        print(f"Error: Directory '{project_name}' already exists")
        return 1

    # Create project structure
    dirs = [
        project_dir,
        project_dir / "templates",
        project_dir / "policies",
        project_dir / ".infracode" / "state",
        project_dir / ".infracode" / "history",
        project_dir / ".infracode" / "vault",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Create starter template
    starter_template = {
        "infracode": {"version": "1.0"},
        "name": project_name,
        "description": f"{project_name} infrastructure",
        "provider": "aws",
        "variables": {
            "environment": {"type": "string", "default": "dev", "description": "Deployment environment"},
            "region": {"type": "string", "default": "us-east-1", "description": "AWS region"},
        },
        "resources": {},
        "outputs": {},
    }

    import yaml
    (project_dir / "infrastructure.yaml").write_text(
        yaml.dump(starter_template, default_flow_style=False, sort_keys=False),
        encoding="utf-8"
    )

    # Create .gitignore
    (project_dir / ".gitignore").write_text(
        ".infracode/state/\n.infracode/vault/\n.env\n*.pem\n*.key\n",
        encoding="utf-8"
    )

    # Init git
    git = GitIntegration(str(project_dir))
    git.init_repo()
    git.commit_changes(f"Initialize InfraCode project: {project_name}")

    print(f"✓ Project '{project_name}' initialized successfully")
    print(f"  → Edit {project_name}/infrastructure.yaml to define your infrastructure")
    print(f"  → Run: cd {project_name} && python -m cli.main plan --config infrastructure.yaml")
    return 0


def cmd_validate(args):
    """Validate a template."""
    engine = InfraEngine()
    template = engine.load_template(args.template)
    errors = engine.validate_template(template)

    for item in errors:
        level = item["level"].upper()
        icon = "✓" if level == "INFO" else "✗" if level == "ERROR" else "⚠"
        print(f"  {icon} [{level}] {item['message']}")

    has_errors = any(e["level"] == "error" for e in errors)
    return 1 if has_errors else 0


def cmd_plan(args):
    """Generate and display an execution plan."""
    state = StateManager()
    engine = InfraEngine(state_manager=state)

    variables = {}
    if args.var:
        for v in args.var:
            key, val = v.split("=", 1)
            variables[key] = val

    template = engine.load_template(args.config, variables)
    plan_data = engine.plan(template)

    plan_engine = PlanEngine()
    plan = plan_engine.generate_plan(template.resources, state.get_resources(), template.name)

    print(plan.format_text())
    return 0


def cmd_apply(args):
    """Apply infrastructure changes."""
    state = StateManager()
    engine = InfraEngine(state_manager=state)
    vc = VersionControl()

    variables = {}
    if args.var:
        for v in args.var:
            key, val = v.split("=", 1)
            variables[key] = val

    template = engine.load_template(args.config, variables)
    plan_data = engine.plan(template)

    # Show plan summary
    summary = plan_data["summary"]
    print(f"\nPlan: {summary['create']} to create, {summary['update']} to update, {summary['delete']} to delete")

    if not args.auto_approve:
        response = input("\nDo you want to apply these changes? (yes/no): ")
        if response.lower() != "yes":
            print("Apply cancelled.")
            return 0

    # Record change
    change = vc.record_change(
        action="apply",
        template=args.config,
        author=os.environ.get("USER", "cli"),
        resources=[a["resource_id"] for a in plan_data["actions"]],
        plan_summary=plan_data["summary"],
    )

    # Apply
    lock = state.acquire_lock(owner="cli", operation="apply")
    try:
        results = engine.apply(plan_data, auto_approve=True)
        vc.update_status(change.change_id, results["status"])
        print(f"\n✓ Apply complete: {results['status']}")
        if results.get("errors"):
            for err in results["errors"]:
                print(f"  ✗ {err['resource_id']}: {err['error']}")
    finally:
        state.release_lock(lock.lock_id)

    return 0 if results["status"] == "success" else 1


def cmd_scan(args):
    """Security scan a template."""
    engine = InfraEngine()
    template = engine.load_template(args.template)

    scanner = SecurityScanner()
    findings = scanner.scan_template(template)
    report = scanner.generate_report(findings)

    print(f"\n{'='*60}")
    print(f"  Security Scan Report — {template.name}")
    print(f"{'='*60}")
    print(f"  Score: {report['score']}/100")
    print(f"  Total Findings: {report['total_findings']}")
    print(f"  CRITICAL: {report['severity_breakdown']['CRITICAL']}")
    print(f"  HIGH:     {report['severity_breakdown']['HIGH']}")
    print(f"  MEDIUM:   {report['severity_breakdown']['MEDIUM']}")
    print(f"  LOW:      {report['severity_breakdown']['LOW']}")

    if findings:
        print(f"\nFindings:")
        for f in findings:
            icon = "🔴" if f.severity == "CRITICAL" else "🟠" if f.severity == "HIGH" else "🟡"
            print(f"  {icon} [{f.severity}] {f.rule_id}: {f.title}")
            print(f"      Resource: {f.resource_id} ({f.resource_type})")
            print(f"      Fix: {f.remediation}")

    return 0 if report["pass"] else 1


def cmd_compliance(args):
    """Run compliance assessment."""
    engine = InfraEngine()
    template = engine.load_template(args.config)

    compliance = ComplianceEngine()
    if args.policy:
        compliance.load_custom_policy(args.policy)

    frameworks = args.frameworks.split(",") if args.frameworks else None
    reports = compliance.assess(template, frameworks)

    for report in reports:
        print(f"\n{'='*60}")
        print(f"  Compliance: {report.framework}")
        print(f"  Score: {report.score:.1f}%")
        print(f"  Passing: {report.passing}/{report.total_controls}")
        print(f"  Failing: {report.failing}")
        print(f"{'='*60}")
        for v in report.violations:
            print(f"  ✗ [{v.severity}] {v.policy_id}: {v.control}")
            print(f"      Resource: {v.resource_id}")
            print(f"      Fix: {v.remediation}")

    return 0


def cmd_state(args):
    """State management commands."""
    state = StateManager()

    if args.state_cmd == "list":
        resources = state.get_resources()
        print(f"\nState: {len(resources)} resources")
        for rid, data in resources.items():
            print(f"  • {rid} ({data.get('type', 'unknown')}) — {data.get('status', 'unknown')}")

    elif args.state_cmd == "versions":
        versions = state.list_versions()
        for v in versions:
            print(f"  v{v['serial']:04d}  {v['timestamp'][:19]}  ({v['resource_count']} resources)")

    elif args.state_cmd == "rollback":
        serial = int(args.serial)
        result = state.rollback(serial)
        print(f"✓ Rolled back to version {serial} (new serial: {result['new_serial']})")

    elif args.state_cmd == "export":
        state.export_state(args.output or "state-export.json")
        print(f"✓ State exported")

    elif args.state_cmd == "unlock":
        state.force_unlock()
        print("✓ State lock removed")

    return 0


def cmd_history(args):
    """Show change history."""
    vc = VersionControl()
    history = vc.get_history(limit=args.limit)

    print(f"\nChange History ({len(history)} entries):")
    for entry in history:
        status_icon = "✓" if entry["status"] == "success" else "✗" if entry["status"] == "failed" else "⟳"
        print(f"  {status_icon} {entry['change_id'][:12]}  {entry['timestamp'][:19]}  {entry['action']:<10}  {entry['template']}")

    return 0


def cmd_version(args):
    """Show version info."""
    print(BANNER)
    return 0


def main():
    parser = argparse.ArgumentParser(description="InfraCode — Infrastructure as Code Platform")
    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Initialize new project")
    p_init.add_argument("name", help="Project name")

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate template")
    p_validate.add_argument("template", help="Template file path")

    # plan
    p_plan = subparsers.add_parser("plan", help="Generate execution plan")
    p_plan.add_argument("--config", "-c", required=True, help="Template file")
    p_plan.add_argument("--var", action="append", help="Variable (key=value)")

    # apply
    p_apply = subparsers.add_parser("apply", help="Apply changes")
    p_apply.add_argument("--config", "-c", required=True, help="Template file")
    p_apply.add_argument("--auto-approve", action="store_true", help="Skip approval prompt")
    p_apply.add_argument("--var", action="append", help="Variable (key=value)")

    # scan
    p_scan = subparsers.add_parser("scan", help="Security scan template")
    p_scan.add_argument("template", help="Template file")

    # compliance
    p_compliance = subparsers.add_parser("compliance", help="Compliance assessment")
    p_compliance.add_argument("--config", "-c", required=True, help="Template file")
    p_compliance.add_argument("--policy", "-p", help="Custom policy file")
    p_compliance.add_argument("--frameworks", "-f", help="Comma-separated frameworks")

    # state
    p_state = subparsers.add_parser("state", help="State management")
    state_sub = p_state.add_subparsers(dest="state_cmd")
    state_sub.add_parser("list", help="List resources in state")
    state_sub.add_parser("versions", help="List state versions")
    p_rb = state_sub.add_parser("rollback", help="Rollback to version")
    p_rb.add_argument("serial", help="Version serial number")
    p_exp = state_sub.add_parser("export", help="Export state")
    p_exp.add_argument("--output", "-o", help="Output file")
    state_sub.add_parser("unlock", help="Force-unlock state")

    # history
    p_history = subparsers.add_parser("history", help="Show change history")
    p_history.add_argument("--limit", "-n", type=int, default=20, help="Max entries")

    # version
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if not args.command:
        cmd_version(args)
        parser.print_help()
        return 0

    commands = {
        "init": cmd_init,
        "validate": cmd_validate,
        "plan": cmd_plan,
        "apply": cmd_apply,
        "scan": cmd_scan,
        "compliance": cmd_compliance,
        "state": cmd_state,
        "history": cmd_history,
        "version": cmd_version,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
