#!/usr/bin/env python3
"""
Guardian Demo: Multi-Device Modbus TCP PLC Simulator
Simulates industrial PLCs with realistic behavior and programmable anomalies
"""

import sys
import logging
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Callable
from dataclasses import dataclass, asdict
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataStore, ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification, ModbusBasicDeviceIdentification
from pymodbus.pdu import ModbusExceptions
from pymodbus.exceptions import ModbusException

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('ModbusPLCSimulator')


@dataclass
class PLCConfig:
    """Configuration for a simulated PLC device"""
    device_id: int
    device_name: str
    host: str
    port: int
    description: str
    normal_setpoint: int  # Normal operating setpoint (Modbus register)
    normal_sensor_value: int  # Normal sensor reading
    valid_setpoint_range: tuple  # (min, max) valid setpoints


@dataclass
class AnomalyEvent:
    """Represents an anomaly to inject into simulation"""
    timestamp: float
    device_id: int
    anomaly_type: str  # "invalid_setpoint", "unauthorized_command", "protocol_violation"
    description: str
    value: int = None
    duration_seconds: int = 5  # How long anomaly persists


class VirtualPLC:
    """Simulates a single industrial PLC with Modbus TCP interface"""
    
    def __init__(self, config: PLCConfig):
        self.config = config
        self.logger = logging.getLogger(f'VirtualPLC-{config.device_name}')
        
        # Modbus register space (simplified)
        self.holding_registers = [0] * 100  # Registers 0-99
        self.input_registers = [0] * 100    # Registers 100-199 (read-only)
        
        # Initialize with normal values
        self.holding_registers[0] = config.normal_setpoint  # Register 0: Setpoint
        self.input_registers[0] = config.normal_sensor_value  # Register 100: Sensor value
        
        # State tracking
        self.is_running = True
        self.anomaly_active = False
        self.anomaly_end_time = None
        self.last_command_timestamp = None
        self.command_history = []
        
        self.logger.info(f"Initialized: {config.description}")
    
    def simulate_normal_operation(self):
        """Simulate realistic PLC behavior"""
        if self.anomaly_active and time.time() > self.anomaly_end_time:
            self.anomaly_active = False
            self.logger.info(f"Anomaly ended on {self.config.device_name}")
        
        # Simulate sensor value oscillating around normal
        base_value = self.config.normal_sensor_value
        variance = 5
        self.input_registers[0] = base_value + (hash(time.time()) % variance)
    
    def inject_anomaly(self, anomaly: AnomalyEvent):
        """Inject an anomaly into the PLC for demo purposes"""
        if anomaly.device_id != self.config.device_id:
            return
        
        self.logger.warning(f"ANOMALY INJECTED: {anomaly.anomaly_type} - {anomaly.description}")
        self.anomaly_active = True
        self.anomaly_end_time = time.time() + anomaly.duration_seconds
        
        if anomaly.anomaly_type == "invalid_setpoint":
            # Set invalid value outside normal range
            invalid_value = anomaly.value if anomaly.value else self.config.valid_setpoint_range[1] + 100
            self.holding_registers[0] = invalid_value
            self.logger.error(f"INVALID SETPOINT: {invalid_value} (valid range: {self.config.valid_setpoint_range})")
        
        elif anomaly.anomaly_type == "unauthorized_command":
            # Simulate unauthorized write
            self.holding_registers[1] = anomaly.value if anomaly.value else 9999
            self.logger.error(f"UNAUTHORIZED COMMAND: Write to register 1 = {anomaly.value}")
        
        elif anomaly.anomaly_type == "protocol_violation":
            # Write to protected register
            self.holding_registers[99] = anomaly.value if anomaly.value else 1
            self.logger.error(f"PROTOCOL VIOLATION: Write to protected register 99")
    
    def get_status(self) -> Dict:
        """Return current PLC status"""
        return {
            "device_id": self.config.device_id,
            "device_name": self.config.device_name,
            "description": self.config.description,
            "timestamp": datetime.now().isoformat(),
            "is_anomaly_active": self.anomaly_active,
            "setpoint": self.holding_registers[0],
            "sensor_value": self.input_registers[0],
            "valid_range": self.config.valid_setpoint_range
        }


class ModbusPLCSimulatorServer:
    """Manages multiple virtual PLCs and Modbus TCP server"""
    
    def __init__(self, plc_configs: List[PLCConfig]):
        self.plc_configs = plc_configs
        self.plcs = {}
        self.logger = logging.getLogger('ModbusPLCSimulatorServer')
        self.anomaly_queue: List[AnomalyEvent] = []
        self.simulation_thread = None
        self.is_running = False
        
        # Initialize PLCs
        for config in plc_configs:
            self.plcs[config.device_id] = VirtualPLC(config)
        
        self.logger.info(f"Initialized {len(self.plcs)} virtual PLCs")
    
    def start_simulation(self):
        """Start the simulation loop"""
        self.is_running = True
        self.simulation_thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self.simulation_thread.start()
        self.logger.info("Simulation loop started")
    
    def _simulation_loop(self):
        """Main simulation loop: update PLC states, inject anomalies"""
        while self.is_running:
            try:
                # Update all PLCs
                for plc in self.plcs.values():
                    plc.simulate_normal_operation()
                
                # Process queued anomalies
                if self.anomaly_queue:
                    anomaly = self.anomaly_queue.pop(0)
                    if anomaly.timestamp <= time.time():
                        plc_id = anomaly.device_id
                        if plc_id in self.plcs:
                            self.plcs[plc_id].inject_anomaly(anomaly)
                
                # Log status periodically
                if int(time.time()) % 10 == 0:
                    for plc in self.plcs.values():
                        status = plc.get_status()
                        self.logger.info(f"Status: {json.dumps(status)}")
                
                time.sleep(0.5)
            
            except Exception as e:
                self.logger.error(f"Simulation loop error: {e}")
                time.sleep(1)
    
    def queue_anomaly(self, anomaly: AnomalyEvent):
        """Queue an anomaly to be injected at a specific time"""
        self.anomaly_queue.append(anomaly)
        self.logger.info(f"Queued anomaly: {anomaly.anomaly_type} for device {anomaly.device_id}")
    
    def get_all_status(self) -> Dict:
        """Get status of all PLCs"""
        return {
            "timestamp": datetime.now().isoformat(),
            "devices": [plc.get_status() for plc in self.plcs.values()]
        }
    
    def shutdown(self):
        """Gracefully shut down"""
        self.is_running = False
        self.logger.info("Shutting down simulation")


def setup_modbus_datastore(simulator: ModbusPLCSimulatorServer) -> ModbusServerContext:
    """Create Modbus datastore that syncs with simulator"""
    store = ModbusSequentialDataStore()
    context = ModbusSlaveContext(hr=store, ir=store, di=store, co=store)
    slave_context = {0x00: context}
    return ModbusServerContext(slave_context, single=False)


def main():
    """Main entry point"""
    
    # Define PLC configurations
    plc_configs = [
        PLCConfig(
            device_id=1,
            device_name="Injection_Molding_PLC_1",
            host="0.0.0.0",
            port=5020,
            description="Primary injection molding machine (Plant A)",
            normal_setpoint=250,  # Temperature in Celsius (as integer)
            normal_sensor_value=248,
            valid_setpoint_range=(200, 300)
        ),
        PLCConfig(
            device_id=2,
            device_name="Injection_Molding_PLC_2",
            host="0.0.0.0",
            port=5021,
            description="Secondary injection molding machine (Plant A)",
            normal_setpoint=220,
            normal_sensor_value=218,
            valid_setpoint_range=(180, 280)
        ),
        PLCConfig(
            device_id=3,
            device_name="Packaging_Conveyor_PLC",
            host="0.0.0.0",
            port=5022,
            description="Automated packaging conveyor (Plant B)",
            normal_setpoint=50,  # Speed in arbitrary units
            normal_sensor_value=49,
            valid_setpoint_range=(20, 100)
        ),
        PLCConfig(
            device_id=4,
            device_name="Quality_Inspection_PLC",
            host="0.0.0.0",
            port=5023,
            description="Quality inspection system (Plant B)",
            normal_setpoint=1,  # Enable = 1
            normal_sensor_value=1,
            valid_setpoint_range=(0, 1)
        ),
    ]
    
    # Initialize simulator
    simulator = ModbusPLCSimulatorServer(plc_configs)
    simulator.start_simulation()
    
    # Example: Queue some anomalies for demo
    # These will be injected at specific times
    anomaly_delay = 30  # Inject anomaly 30 seconds after start
    
    simulator.queue_anomaly(AnomalyEvent(
        timestamp=time.time() + anomaly_delay,
        device_id=1,
        anomaly_type="invalid_setpoint",
        description="Unauthorized temperature setpoint change (PLC 1)",
        value=450  # Way too high
    ))
    
    simulator.queue_anomaly(AnomalyEvent(
        timestamp=time.time() + anomaly_delay + 10,
        device_id=3,
        anomaly_type="unauthorized_command",
        description="Unauthorized conveyor speed command (PLC 3)",
        value=200  # Exceeds max speed
    ))
    
    logger.info("Modbus TCP PLC Simulator running")
    logger.info("Devices:")
    for config in plc_configs:
        logger.info(f"  - {config.device_name} (ID: {config.device_id}, Port: {config.port})")
    
    logger.info("Anomalies queued for demo (30 seconds after start)")
    logger.info("Press Ctrl+C to exit")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        simulator.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
