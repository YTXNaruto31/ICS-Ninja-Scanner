#!/usr/bin/env python3
"""
MottaSec ICS Ninja Scanner - A multi-protocol Industrial Control System security scanner.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import os
import sys
import time
import click
import yaml
import json
import csv
import ipaddress
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

# Import scanner modules
from scanners.modbus_scanner import ModbusScanner
from scanners.dnp3_scanner import DNP3Scanner
from scanners.bacnet_scanner import BACnetScanner
from scanners.s7_scanner import S7Scanner
from scanners.ethernet_ip_scanner import EthernetIPScanner
from scanners.opcua_scanner import OPCUAScanner
from scanners.profinet_scanner import ProfinetScanner
from scanners.iec104_scanner import IEC104Scanner
from scanners.hart_scanner import HARTScanner
from scanners.snmp_scanner import SNMPScanner
from scanners.mqtt_scanner import MQTTScanner

# Import utilities
from utils.network import parse_target_input, port_scan
from utils.reporting import generate_report
from utils.config import load_config

# Initialize console
console = Console()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("MottaSec.NinjaScanner")

# Version
VERSION = "1.0.0"
CODENAME = "MottaSec-Fox"

# Protocol to scanner class mapping
PROTOCOL_SCANNERS = {
    "modbus": ModbusScanner,
    "dnp3": DNP3Scanner,
    "bacnet": BACnetScanner,
    "s7": S7Scanner,
    "ethernet-ip": EthernetIPScanner,
    "opcua": OPCUAScanner,
    "profinet": ProfinetScanner,
    "iec104": IEC104Scanner,
    "hart": HARTScanner,
    "snmp": SNMPScanner,
    "mqtt": MQTTScanner
}

def validate_protocols(ctx, param, value):
    """Validate the protocols parameter."""
    if not value:
        return []
    
    if value.lower() == 'all':
        # Return all protocols without invoking Click's command system
        # This fixes the issue with test_validate_protocols_all
        return list(PROTOCOL_SCANNERS.keys())
    
    protocols = [p.strip().lower() for p in value.split(',')]
    invalid_protocols = [p for p in protocols if p not in PROTOCOL_SCANNERS]
    
    if invalid_protocols:
        raise click.BadParameter(
            f"Invalid protocols: {', '.join(invalid_protocols)}. "
            f"Available protocols: {', '.join(PROTOCOL_SCANNERS.keys())}"
        )
    
    return protocols

def print_mottasec_banner():
    """Print the MottaSec ICS Ninja Scanner banner."""
    banner = f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║  [bold blue]MottaSec ICS Ninja Scanner v{VERSION}[/bold blue] - [bold yellow]"{CODENAME}"[/bold yellow]                         ║
    ║                                                                              ║
    ║  [cyan]Developed by the MottaSec Ghost Team[/cyan]                                   ║
    ║  [cyan]The unseen guardians of industrial systems[/cyan]                             ║
    ║                                                                              ║
    ║  [green]"We find what others miss"[/green]                                           ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, border_style="blue"))

@click.group()
def cli():
    """MottaSec ICS Ninja Scanner - A multi-protocol Industrial Control System security scanner."""
    pass

@cli.command()
@click.option('--target', required=True, help='Target IP, IP range, or subnet')
@click.option('--protocols', required=True, callback=validate_protocols, 
              help='Comma-separated list of protocols or \'all\'')
@click.option('--intensity', type=click.Choice(['low', 'medium', 'high']), default='low',
              help='Scan intensity level')
@click.option('--output-format', type=click.Choice(['txt', 'json', 'csv', 'all']), default='txt',
              help='Output format')
@click.option('--output-file', help='Output file name (without extension)')
@click.option('--port-range', help='Custom port range to scan (default: protocol standard ports)')
@click.option('--timeout', default=5, help='Connection timeout in seconds')
@click.option('--threads', default=10, help='Number of threads for parallel scanning')
@click.option('--no-verify', is_flag=True, help='Disable SSL/TLS verification for protocols that support it')
@click.option('--debug', is_flag=True, help='Enable debug logging')
def scan(target, protocols, intensity, output_format, output_file, port_range, timeout, threads, no_verify, debug):
    """Run a security scan against ICS targets."""
    # Set debug logging if requested
    if debug:
        logging.getLogger("MottaSec").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    start_time = time.time()
    
    # Print banner
    print_mottasec_banner()
    
    logger.info(f"Starting scan with intensity: {intensity}")
    logger.info(f"Target: {target}")
    logger.info(f"Protocols: {', '.join(protocols)}")
    
    # Parse target input
    try:
        targets = parse_target_input(target)
        console.print(f"[green]Resolved {len(targets)} target(s) from input: {target}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error parsing target: {str(e)}[/bold red]")
        sys.exit(1)
    
    # Load configuration
    config = load_config()
    
    # Initialize scan results
    scan_results = {
        "metadata": {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "protocols": protocols,
            "intensity": intensity,
            "version": VERSION,
            "codename": CODENAME,
            "scanner": "MottaSec ICS Ninja Scanner"
        },
        "results": {}
    }
    
    # Create scanners for each protocol
    active_scanners = {}
    for protocol in protocols:
        scanner_class = PROTOCOL_SCANNERS[protocol]
        scanner_instance = scanner_class(intensity=intensity, timeout=timeout, verify=not no_verify)
        active_scanners[protocol] = scanner_instance
        logger.debug(f"Initialized {protocol} scanner with intensity {intensity}")
    
    # Function to scan a single target
    def scan_target(ip):
        target_results = {}
        
        # First perform port scan if port range is specified
        open_ports = []
        if port_range:
            logger.debug(f"Scanning ports {port_range} on {ip}")
            open_ports = port_scan(str(ip), port_range, timeout)
            if open_ports:
                logger.debug(f"Found open ports on {ip}: {open_ports}")
        
        # Run each protocol scanner against the target
        for protocol, scanner in active_scanners.items():
            try:
                logger.debug(f"Running {protocol} scan on {ip}")
                scanner.start_scan_timer()
                protocol_result = scanner.scan(str(ip), open_ports)
                scan_duration = scanner.stop_scan_timer()
                
                if protocol_result:
                    # Add scan duration to results
                    if 'scan_info' not in protocol_result:
                        protocol_result['scan_info'] = {}
                    protocol_result['scan_info']['duration_seconds'] = scan_duration
                    protocol_result['scan_info']['scanner'] = scanner.name
                    target_results[protocol] = protocol_result
                    
                    logger.debug(f"Found {len(protocol_result.get('issues', []))} issues with {protocol} on {ip}")
            except Exception as e:
                logger.error(f"Error scanning {ip} with {protocol}: {str(e)}")
                console.print(f"[bold red]Error scanning {ip} with {protocol}: {str(e)}[/bold red]")
        
        return str(ip), target_results
    
    # Scan all targets in parallel
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        scan_task = progress.add_task("[bold blue]Scanning targets...", total=len(targets))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in targets:
                future = executor.submit(scan_target, ip)
                futures.append(future)
            
            for future in futures:
                ip, target_results = future.result()
                if target_results:
                    scan_results["results"][ip] = target_results
                progress.update(scan_task, advance=1)
    
    # Processing finished
    elapsed_time = time.time() - start_time
    console.print(f"[bold green]Scan completed in {elapsed_time:.2f} seconds[/bold green]")
    
    # Generate summary
    total_issues = 0
    critical_issues = 0
    high_issues = 0
    medium_issues = 0
    low_issues = 0
    info_issues = 0
    
    for ip, protocols in scan_results["results"].items():
        for protocol, findings in protocols.items():
            if 'issues' in findings:
                for issue in findings['issues']:
                    total_issues += 1
                    severity = issue.get('severity', '').lower()
                    if severity == 'critical':
                        critical_issues += 1
                    elif severity == 'high':
                        high_issues += 1
                    elif severity == 'medium':
                        medium_issues += 1
                    elif severity == 'low':
                        low_issues += 1
                    elif severity == 'info':
                        info_issues += 1
    
    # Display summary table
    table = Table(title="MottaSec ICS Ninja Scanner - Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total targets", str(len(targets)))
    table.add_row("Targets with findings", str(len(scan_results["results"])))
    table.add_row("Total issues found", str(total_issues))
    table.add_row("Critical issues", f"[bold red]{critical_issues}[/bold red]")
    table.add_row("High issues", f"[red]{high_issues}[/red]")
    table.add_row("Medium issues", f"[yellow]{medium_issues}[/yellow]")
    table.add_row("Low issues", f"[blue]{low_issues}[/blue]")
    table.add_row("Info issues", f"[cyan]{info_issues}[/cyan]")
    table.add_row("Protocols scanned", ", ".join(protocols))
    table.add_row("Scan intensity", intensity)
    table.add_row("Scan duration", f"{elapsed_time:.2f} seconds")
    
    console.print(table)
    
    # Generate reports
    if output_file:
        output_formats = [output_format] if output_format != 'all' else ['txt', 'json', 'csv']
        for format_type in output_formats:
            report_path = generate_report(scan_results, format_type, output_file)
            console.print(f"[bold green]Report saved to: {report_path}[/bold green]")
    else:
        # Print results to console
        for ip, protocols in scan_results["results"].items():
            console.print(f"\n[bold blue]Results for target: {ip}[/bold blue]")
            for protocol, findings in protocols.items():
                console.print(f"\n[bold cyan]Protocol: {protocol.upper()}[/bold cyan]")
                
                if 'device_info' in findings:
                    console.print("[green]Device Information:[/green]")
                    for key, value in findings['device_info'].items():
                        console.print(f"  [cyan]{key}:[/cyan] {value}")
                
                if 'issues' in findings:
                    console.print("\n[yellow]Issues Found:[/yellow]")
                    for issue in findings['issues']:
                        severity = issue.get('severity', 'unknown')
                        severity_color = {
                            'critical': 'red',
                            'high': 'red',
                            'medium': 'yellow',
                            'low': 'cyan',
                            'info': 'blue'
                        }.get(severity.lower(), 'white')
                        
                        console.print(f"  [[{severity_color}]{severity}[/{severity_color}]] {issue['description']}")
                        if 'details' in issue:
                            console.print(f"    Details: {issue['details']}")
                        if 'remediation' in issue:
                            console.print(f"    Remediation: {issue['remediation']}")
                
                if not findings.get('issues'):
                    console.print("[green]  No issues detected[/green]")
    
    # Final message
    console.print(f"\n[bold green]MottaSec ICS Ninja Scanner completed successfully![/bold green]")
    console.print("[yellow]If you found this tool useful, contact us at ghost@mottasec.com[/yellow]")

@cli.command()
def list():
    """List available protocols and scan options."""
    print_mottasec_banner()
    
    console.print("[bold blue]Available Protocols[/bold blue]")
    for protocol in sorted(PROTOCOL_SCANNERS.keys()):
        console.print(f"  - [cyan]{protocol}[/cyan]")
    
    console.print("\n[bold blue]Intensity Levels[/bold blue]")
    console.print("  - [green]low[/green]: Passive scan (device discovery, version detection)")
    console.print("  - [yellow]medium[/yellow]: Query system state (read registers, security settings)")
    console.print("  - [red]high[/red]: Simulated attack vectors (unauthenticated control attempts, write tests)")
    
    console.print("\n[yellow]Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.[/yellow]")
    console.print("[yellow]Contact us at ghost@mottasec.com[/yellow]")

@cli.command()
def version():
    """Show the version of the tool."""
    print_mottasec_banner()
    console.print(f"MottaSec ICS Ninja Scanner v{VERSION} - Codename: '{CODENAME}'")
    console.print("[yellow]Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.[/yellow]")

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.exception("An unexpected error occurred")
        console.print(f"\n[bold red]An error occurred: {str(e)}[/bold red]")
        sys.exit(1) 