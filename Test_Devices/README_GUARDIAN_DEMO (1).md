# Guardian Demo: Multi-Device Modbus TCP PLC Simulator

Complete Docker-based simulation environment for demonstrating Guardian SG-X device-layer security with realistic industrial PLCs and programmable anomalies.

\---

## Overview

This demo environment includes:

* **4 Virtual PLCs**: Simulating realistic injection molding, packaging, and quality inspection systems
* **Modbus TCP Protocol**: Industry-standard industrial protocol that Guardian monitors
* **Realistic Behavior**: Each PLC maintains state, sensor values, and valid parameter ranges
* **Programmable Anomalies**: Inject unauthorized commands, invalid setpoints, supply chain implants, and insider threats
* **Demo Scenarios**: Pre-scripted demonstrations of Guardian's threat detection and autonomous response

\---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Guardian SG-X Device                  Modbus TCP Simulator    │
│  ┌──────────────────┐                  ┌──────────────────┐   │
│  │ Guardian Edge    │◄─────Modbus──────│ PLC 1: Injection │   │
│  │ Protection       │    TCP (5020)    │ Molding (250°C)  │   │
│  │                  │                  │                  │   │
│  │ • Circle of      │◄─────Modbus──────│ PLC 2: Injection │   │
│  │   Trust          │    TCP (5021)    │ Molding (220°C)  │   │
│  │ • Virtual Shift  │                  │                  │   │
│  │ • TPM Verify     │◄─────Modbus──────│ PLC 3: Conveyor  │   │
│  │ • Autonomous     │    TCP (5022)    │ (Speed 50)       │   │
│  │   Response       │                  │                  │   │
│  │                  │◄─────Modbus──────│ PLC 4: Quality   │   │
│  │ Web UI: 8443     │    TCP (5023)    │ Inspection       │   │
│  │ API: 5000        │                  │                  │   │
│  └──────────────────┘                  └──────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

\---

## Getting Started

### Prerequisites

* Docker \& Docker Compose installed
* 2GB+ free disk space
* Ports 8443, 5000, 5020-5023 available

### Quick Start

```bash
# 1. Navigate to demo directory
cd /path/to/guardian-demo

# 2. Build and start containers
docker-compose -f docker-compose-guardian-demo.yml up -d

# 3. Verify containers are running
docker-compose -f docker-compose-guardian-demo.yml ps

# 4. Check Guardian is ready
curl -k https://localhost:8443/api/health

# 5. Run a demo scenario
docker exec modbus\_plc\_simulator python3 demo\_scenario\_controller.py
```

### Stopping the Demo

```bash
docker-compose -f docker-compose-guardian-demo.yml down
```

\---

## Virtual PLCs

### PLC 1: Injection Molding (Primary)

**Port:** 5020 (Modbus TCP)  
**Normal Setpoint:** 250°C (valid range: 200-300°C)  
**Sensor Value:** \~248°C  
**Use Case:** Primary molding machine; high-value production equipment

**Modbus Registers:**

* Register 0: Setpoint (R/W)
* Register 100: Sensor value (Read-only)

### PLC 2: Injection Molding (Secondary)

**Port:** 5021 (Modbus TCP)  
**Normal Setpoint:** 220°C (valid range: 180-280°C)  
**Sensor Value:** \~218°C  
**Use Case:** Secondary molding machine; lower temperature operation

### PLC 3: Packaging Conveyor

**Port:** 5022 (Modbus TCP)  
**Normal Speed:** 50 units (valid range: 20-100)  
**Use Case:** Automated packaging line; high-speed equipment

### PLC 4: Quality Inspection

**Port:** 5023 (Modbus TCP)  
**Normal Enable:** 1 (valid range: 0-1, binary)  
**Use Case:** Quality assurance system

\---

## Demo Scenarios

Run demo scenarios using the scenario controller:

```bash
docker exec modbus\_plc\_simulator python3 demo\_scenario\_controller.py
```

### Scenario 1: Normal Operation (Baseline)

**Duration:** 60 seconds  
**Purpose:** Establish baseline behavior with all PLCs operating normally.  
**Key Points:**

* All devices send normal Modbus values
* No anomalies
* Guardian monitoring with zero alerts
* Shows Guardian's passive observation capability

**Expected Guardian Behavior:** No incidents, baseline metrics

\---

### Scenario 2: Single Device Anomaly Detection

**Duration:** 45 seconds  
**Purpose:** Demonstrate detection and containment of a single invalid setpoint change.  
**Attack Sequence:**

1. Unauthorized command sets PLC 1 temperature to 450°C (outside 200-300°C valid range)
2. Guardian detects invalid setpoint violation
3. Guardian engages Byzantine consensus (peer voting)
4. Device quarantined in <3 seconds
5. Alert sent to Cylenium Cloud

**Expected Guardian Behavior:**

* ✅ Detects invalid setpoint in <100ms
* ✅ Validates via peer consensus
* ✅ Quarantines device <3 seconds
* ✅ Sends alert to management layer
* ✅ Prevents cascading failure

\---

### Scenario 3: Multi-Device Cascade Attack

**Duration:** 60 seconds  
**Purpose:** Show Guardian's cross-device threat correlation and coordinated response.  
**Attack Sequence:**

1. Attacker increases Packaging Conveyor speed to 200 (exceeds max 100)
2. Seconds later, attacker disables Quality Inspection system
3. Guardian detects both anomalies
4. Guardian cross-site analysis identifies coordinated pattern
5. Both devices quarantined
6. Attack contained before cascading

**Expected Guardian Behavior:**

* ✅ Detects individual anomalies on each device
* ✅ Correlates pattern across devices (multi-device attack signature)
* ✅ Isolates compromised devices
* ✅ Preserves uncompromised devices (PLC 1 \& 2 continue operating)
* ✅ Sends detailed correlation alert

\---

### Scenario 4: Supply Chain Implant Detection

**Duration:** 50 seconds  
**Purpose:** Demonstrate TPM attestation preventing tampered hardware enrollment.  
**Scenario:**

1. New equipment (PLC 5, compromised during manufacturing) attempts to join Circle of Trust
2. Guardian validates hardware TPM 2.0 signature
3. Signature mismatch detected (firmware was tampered with)
4. Device enrollment DENIED
5. Device blocked from joining Circle
6. Hardware returned to vendor
7. Legitimate replacement (PLC 5B) arrives and successfully enrolls

**Expected Guardian Behavior:**

* ✅ Validates TPM attestation on all new devices
* ✅ Detects tampered hardware before enrollment
* ✅ Prevents implanted devices from joining network
* ✅ Logs forensic data for investigation
* ✅ Accepts legitimate replacements with valid TPM

**Key Differentiator:** This prevents supply chain attacks at the *root*—unlike network tools that can only detect behavior after infection.

\---

### Scenario 5: Insider Threat - Unauthorized Command

**Duration:** 55 seconds  
**Purpose:** Show that even trusted operators cannot bypass device policy.  
**Scenario:**

1. Operator with legitimate VPN access connects to PLC 1
2. Operator (intentionally or due to compromise) attempts to set temperature to 400°C (outside policy)
3. Guardian detects: signature is valid (trusted operator), BUT value violates bounds
4. Byzantine consensus across Circle members required
5. Other PLCs reject the command (policy consensus fails)
6. Command BLOCKED; device enters warning state
7. Alert sent to admin with audit trail
8. Admin reviews and revokes operator's setpoint-change privileges

**Expected Guardian Behavior:**

* ✅ Distinguishes trusted source from invalid command
* ✅ Applies device-layer policy even for trusted operators
* ✅ Requires quorum agreement (Byzantine resilience)
* ✅ Generates detailed audit trail (actor, time, command, rejection reason)
* ✅ Enables policy updates based on incident investigation

\---

## Running Custom Anomalies

To inject custom anomalies into a running simulator:

### Edit `modbus\_plc\_simulator.py`

In the `main()` function, add to the anomaly queue:

```python
simulator.queue\_anomaly(AnomalyEvent(
    timestamp=time.time() + 30,  # Inject at 30 seconds
    device\_id=1,  # Target PLC 1
    anomaly\_type="invalid\_setpoint",  # Type of anomaly
    description="Custom test anomaly",
    value=999,  # Custom value
    duration\_seconds=5  # How long anomaly persists
))
```

**Anomaly Types:**

* `invalid\_setpoint`: Set register outside valid range
* `unauthorized\_command`: Write to protected registers
* `protocol\_violation`: Send malformed Modbus messages

### Rebuild and restart:

```bash
docker-compose -f docker-compose-guardian-demo.yml down
docker-compose -f docker-compose-guardian-demo.yml up -d --build
```

\---

## Monitoring Guardian's Response

### Guardian Web UI

Access Guardian's management interface:

```
https://localhost:8443
```

**Capabilities:**

* View real-time device status
* Monitor active Circle of Trust memberships
* Review incident history and alerts
* Manage device policies

### Guardian API

Query Guardian status programmatically:

```bash
# Get device inventory
curl -k https://localhost:5000/api/devices

# Get active alerts
curl -k https://localhost:5000/api/alerts

# Get device status
curl -k https://localhost:5000/api/devices/{device\_id}/status
```

### Docker Logs

View Guardian and simulator logs:

```bash
# Guardian logs
docker logs -f guardian\_sg\_x

# Simulator logs
docker logs -f modbus\_plc\_simulator
```

\---

## Demo Workflow (For Presentations)

### Pre-Demo Setup

```bash
# 1. Start containers 10 minutes before demo
docker-compose -f docker-compose-guardian-demo.yml up -d

# 2. Verify all services healthy
docker-compose -f docker-compose-guardian-demo.yml ps

# 3. Open Guardian Web UI in browser
# https://localhost:8443

# 4. Verify all 4 PLCs are discovered and joined Circle of Trust
```

### During Demo

**Segment 1: Baseline (2 min)**

* Show Guardian dashboard with all 4 PLCs operating normally
* Highlight: "Zero threats detected. All devices in healthy Circle of Trust."

**Segment 2: Run Scenario 2 (Single Anomaly)**

* Execute: `docker exec modbus\_plc\_simulator python3 demo\_scenario\_controller.py` → Select "2"
* Live demo of unauthorized setpoint change
* Show: Guardian detects threat, correlates with policy, and quarantines device
* Highlight: "<3 second response—no SOC triage, no human delay"

**Segment 3: Run Scenario 3 (Multi-Device Attack)**

* Execute scenario "3"
* Show coordinated attack across conveyor and quality system
* Highlight: "Guardian detects cross-device pattern, isolates both, preserves uncompromised devices"

**Segment 4: Run Scenario 4 (Supply Chain)**

* Execute scenario "4"
* Show TPM attestation blocking tampered hardware
* Highlight: "Hardware-rooted trust prevents supply chain implants—something network tools cannot do"

**Segment 5: Q\&A**

* Show audit logs in Guardian (who tried what, when, why it was blocked)
* Demonstrate policy update capability (change device rules on-the-fly)
* Answer customer concerns about false positives (Guardian's Byzantine consensus minimizes them)

\---

## Troubleshooting

### Containers won't start

```bash
# Check for port conflicts
lsof -i :8443
lsof -i :5020-5023

# View detailed logs
docker-compose -f docker-compose-guardian-demo.yml logs

# Rebuild from scratch
docker-compose -f docker-compose-guardian-demo.yml down --volumes
docker system prune -a
docker-compose -f docker-compose-guardian-demo.yml up -d --build
```

### Guardian not discovering PLCs

```bash
# Test Modbus connectivity from Guardian container
docker exec guardian\_sg\_x nc -zv modbus\_plc\_simulator 5020

# Check if simulator is running
docker logs modbus\_plc\_simulator | tail -20
```

### Anomalies not triggering

```bash
# Verify simulator is running
docker exec modbus\_plc\_simulator python3 -c "print('Simulator responding')"

# Check anomaly queue in logs
docker logs modbus\_plc\_simulator | grep "ANOMALY"
```

\---

## Files Included

* `modbus\_plc\_simulator.py` — Virtual PLC simulator with anomaly injection
* `Dockerfile.modbus` — Container definition for simulator
* `docker-compose-guardian-demo.yml` — Orchestration (Guardian + Simulator)
* `demo\_scenario\_controller.py` — Scenario execution engine
* `README\_GUARDIAN\_DEMO.md` — This file

\---

## Next Steps

After running the demo:

1. **Collect Metrics**: Guardian's detection latency, false positive rate, response time
2. **Review Audit Logs**: Show customer exact forensic trail in Cylenium Cloud
3. **Discuss Deployment**: Talk through phased rollout to customer's actual plants
4. **Trial Proposal**: Offer free 2-week passive discovery assessment

\---

## Support \& Customization

For custom scenarios or Guardian integration questions, contact the Cervais team.

\---

**Guardian + Cylenium Cloud: Device-layer security that scales from single plant to enterprise.**

