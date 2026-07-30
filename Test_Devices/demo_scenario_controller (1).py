#!/usr/bin/env python3
"""
Guardian Demo Scenario Controller
Orchestrates normal operations and anomaly injection for demonstrations
"""

import time
import json
import logging
from datetime import datetime
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger('DemoScenarioController')


class DemoScenario(Enum):
    """Predefined demonstration scenarios"""
    NORMAL_OPERATION = "normal_operation"
    SINGLE_ANOMALY = "single_anomaly"
    MULTI_DEVICE_ATTACK = "multi_device_attack"
    SUPPLY_CHAIN_IMPLANT = "supply_chain_implant"
    INSIDER_THREAT = "insider_threat"


class GuardianDemoScenario:
    """Base class for demo scenarios"""
    
    def __init__(self, name: str, description: str, duration_seconds: int):
        self.name = name
        self.description = description
        self.duration_seconds = duration_seconds
        self.start_time = None
        self.events = []  # List of (delay_seconds, event_description, action_function)
    
    def run(self):
        """Execute the scenario"""
        logger.info(f"\n{'='*80}")
        logger.info(f"SCENARIO: {self.name}")
        logger.info(f"DESCRIPTION: {self.description}")
        logger.info(f"DURATION: {self.duration_seconds} seconds")
        logger.info(f"{'='*80}\n")
        
        self.start_time = time.time()
        
        for delay, event_desc, action in self.events:
            # Wait until the event should fire
            while time.time() - self.start_time < delay:
                time.sleep(0.1)
            
            logger.info(f"[+{delay}s] {event_desc}")
            action()
        
        # Wait for remaining duration
        remaining = self.duration_seconds - (time.time() - self.start_time)
        if remaining > 0:
            logger.info(f"\nWaiting {remaining:.0f} more seconds for scenario to complete...")
            time.sleep(remaining)
        
        logger.info(f"\n{'='*80}")
        logger.info(f"SCENARIO COMPLETE: {self.name}")
        logger.info(f"{'='*80}\n")


class Scenario_NormalOperation(GuardianDemoScenario):
    """Baseline: All PLCs operating normally"""
    
    def __init__(self):
        super().__init__(
            name="Normal Operation",
            description="All PLCs operating at baseline. No anomalies. Shows Guardian's baseline behavior.",
            duration_seconds=60
        )
        
        self.events = [
            (5, "Injection Molding PLC 1: Setpoint = 250°C, Sensor = 248°C", lambda: None),
            (10, "Injection Molding PLC 2: Setpoint = 220°C, Sensor = 218°C", lambda: None),
            (15, "Packaging Conveyor: Speed = 50 units, Running normally", lambda: None),
            (20, "Quality Inspection: System ENABLED, All checks passing", lambda: None),
            (30, "All devices stable. Guardian monitoring with zero alerts.", lambda: None),
            (40, "Continued normal operation. No threats detected.", lambda: None),
            (50, "Baseline monitoring complete. Ready for anomaly injection.", lambda: None),
        ]


class Scenario_SingleAnomalyDetection(GuardianDemoScenario):
    """Simple: Detect and contain a single invalid setpoint change"""
    
    def __init__(self):
        super().__init__(
            name="Single Device Anomaly Detection",
            description="Unauthorized setpoint change on Injection Molding PLC 1. Guardian detects and quarantines.",
            duration_seconds=45
        )
        
        self.events = [
            (2, "Baseline: All devices normal", lambda: None),
            (5, "ATTACK: Unauthorized command to PLC 1 - Set temperature to 450°C (outside valid range 200-300°C)", 
             lambda: self._log_anomaly("PLC1", "setpoint", 450)),
            (7, "Guardian Detects: Invalid setpoint violation on PLC 1", lambda: None),
            (8, "Guardian Validates: Byzantine consensus = 75% agreement it's a threat", lambda: None),
            (9, "Guardian Responds: Device quarantined in <3 seconds", lambda: None),
            (10, "Guardian Alert: 'Invalid setpoint on PLC 1 - Unauthorized Command Detected'", lambda: None),
            (15, "PLC 1 Status: QUARANTINED - No commands accepted", lambda: None),
            (20, "SOC Notification: Alert sent to Cylenium Cloud and SIEM", lambda: None),
            (30, "Investigation: PLC 1 remains isolated until admin re-enrolls device", lambda: None),
        ]
    
    def _log_anomaly(self, device, anomaly_type, value):
        logger.warning(f"[ANOMALY] {device} {anomaly_type}={value}")


class Scenario_MultiDeviceAttack(GuardianDemoScenario):
    """Coordinated: Attacker tries to compromise multiple devices (cascade attack)"""
    
    def __init__(self):
        super().__init__(
            name="Multi-Device Cascade Attack",
            description="Attacker attempts coordinated attack across 3 devices. Guardian detects pattern.",
            duration_seconds=60
        )
        
        self.events = [
            (2, "Baseline: All 4 devices operating normally", lambda: None),
            (8, "ATTACK PHASE 1: Unauthorized speed increase on Packaging Conveyor (PLC 3)", 
             lambda: self._log_attack("PLC3", "speed", 200)),
            (9, "Guardian Detects: Speed anomaly on PLC 3", lambda: None),
            (10, "ATTACK PHASE 2: Seconds later, attempt to disable Quality Inspection (PLC 4)", 
             lambda: self._log_attack("PLC4", "disable", 0)),
            (11, "Guardian Detects: Disable command on PLC 4 (not authorized)", lambda: None),
            (12, "Guardian Cross-Site Analysis: Detects pattern - multiple coordinated commands", lambda: None),
            (13, "Guardian Verdict: Coordinated attack detected. Quarantining both devices.", lambda: None),
            (14, "PLC 3 & PLC 4 Status: QUARANTINED", lambda: None),
            (15, "Guardian Alert: 'Coordinated attack pattern detected across 2 devices'", lambda: None),
            (20, "Attack contained. Only 2 of 4 devices compromised before Guardian isolation.", lambda: None),
            (30, "Forensics: Guardian logs show exact timestamp and sequence of attack", lambda: None),
            (45, "Uncompromised PLCs (1, 2) continue normal operation through attack", lambda: None),
        ]
    
    def _log_attack(self, device, action, value):
        logger.warning(f"[ATTACK] {device} {action}={value}")


class Scenario_SupplyChainImplant(GuardianDemoScenario):
    """Supply Chain: Tampered device with hidden malware tries to enroll"""
    
    def __init__(self):
        super().__init__(
            name="Supply Chain Implant Detection",
            description="New equipment (compromised during manufacturing) attempts to join Circle of Trust. TPM attestation detects tampering.",
            duration_seconds=50
        )
        
        self.events = [
            (2, "Normal: Existing devices (PLC 1-4) forming healthy Circle of Trust", lambda: None),
            (5, "NEW HARDWARE: New injection molding machine (PLC 5) boots and attempts enrollment", 
             lambda: self._log_enrollment_attempt("PLC5")),
            (6, "Guardian TPM Check: Validating hardware identity (TPM 2.0 attestation)", lambda: None),
            (7, "Guardian Detects: TPM firmware signature mismatch - indicates tampering", lambda: None),
            (8, "Guardian Rejects: Device fails TPM attestation - ENROLLMENT DENIED", lambda: None),
            (9, "Guardian Alert: 'Supply Chain Threat - Device TPM Attestation Failed'", lambda: None),
            (10, "PLC 5 Status: BLOCKED - Not permitted to join Circle of Trust", lambda: None),
            (15, "Isolation: Tampered device cannot communicate with trusted PLCs", lambda: None),
            (20, "Forensics: TPM fingerprint logged and flagged in Cylenium Cloud", lambda: None),
            (30, "Resolution: Hardware returned to vendor for investigation", lambda: None),
            (40, "Legitimate replacement equipment (PLC 5B) arrives with valid TPM", lambda: None),
            (41, "Guardian TPM Check: Valid signature - enrollment APPROVED", lambda: None),
            (42, "PLC 5B joins Circle of Trust successfully", lambda: None),
        ]
    
    def _log_enrollment_attempt(self, device):
        logger.info(f"[ENROLLMENT] {device} attempting to join Circle of Trust")


class Scenario_InsiderThreat(GuardianDemoScenario):
    """Insider: Operator with legitimate access attempts unauthorized command"""
    
    def __init__(self):
        super().__init__(
            name="Insider Threat - Unauthorized Command",
            description="Trusted operator (legitimate network access) attempts to change PLC parameters outside policy.",
            duration_seconds=55
        )
        
        self.events = [
            (2, "Scenario: Operator has VPN access to plant network (normal)", lambda: None),
            (5, "Operator connects to Injection Molding PLC 1 (expected)", lambda: None),
            (8, "Operator attempts to change setpoint from 250°C to 400°C (outside policy)", 
             lambda: self._log_insider_attempt("Operator", "PLC1", "setpoint", 400)),
            (9, "Guardian Detects: Setpoint change violates device policy", lambda: None),
            (10, "Guardian Checks: Command signature = valid (operator has access), BUT value violates bounds", lambda: None),
            (11, "Guardian Validation: Byzantine consensus required - even trusted device must agree", lambda: None),
            (12, "Guardian Result: Other PLCs in Circle reject the command (consensus fails)", lambda: None),
            (13, "Guardian Response: Command BLOCKED and device put in warning state", lambda: None),
            (14, "Guardian Alert: 'Unauthorized parameter change from operator (insider threat)'", lambda: None),
            (15, "PLC 1 Status: MONITORED (not quarantined - trusted source, but command invalid)", lambda: None),
            (20, "Operator receives error: 'Command violates device policy. Contact admin.'", lambda: None),
            (30, "Admin reviews alert and operator's credentials in Cylenium Cloud audit log", lambda: None),
            (35, "Admin confirms: Operator was attempting to bypass safety limits", lambda: None),
            (40, "Admin revokes operator's access policy for temperature setpoint changes", lambda: None),
            (45, "Policy enforcement updated across all PLCs in Circle of Trust", lambda: None),
        ]
    
    def _log_insider_attempt(self, actor, device, param, value):
        logger.warning(f"[INSIDER_ATTEMPT] {actor} tried to set {device}.{param}={value}")


def main():
    """Interactive scenario selection and execution"""
    
    scenarios = {
        "1": Scenario_NormalOperation(),
        "2": Scenario_SingleAnomalyDetection(),
        "3": Scenario_MultiDeviceAttack(),
        "4": Scenario_SupplyChainImplant(),
        "5": Scenario_InsiderThreat(),
    }
    
    print("\n" + "="*80)
    print("GUARDIAN DEMO SCENARIO CONTROLLER")
    print("="*80)
    print("\nAvailable Scenarios:\n")
    
    for key, scenario in scenarios.items():
        print(f"  {key}. {scenario.name}")
        print(f"     {scenario.description}\n")
    
    print("  6. Run all scenarios sequentially")
    print("  q. Quit\n")
    
    choice = input("Select scenario (1-6 or q): ").strip().lower()
    
    if choice == 'q':
        logger.info("Exiting")
        return
    
    elif choice in scenarios:
        scenarios[choice].run()
    
    elif choice == '6':
        logger.info("Running all scenarios sequentially...")
        for scenario in scenarios.values():
            scenario.run()
            time.sleep(3)  # Pause between scenarios
    
    else:
        logger.error("Invalid selection")


if __name__ == "__main__":
    main()
