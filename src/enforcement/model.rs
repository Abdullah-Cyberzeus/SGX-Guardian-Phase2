//! Internal enforcement rule model.
//!
//! This is an OS-agnostic representation of firewall intent.

#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny,
    Masquerade,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConntrackState {
    New,
    Established,
    Related,
    Invalid,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct InterfaceMatch {
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnforcementRule {
    pub action: Action,
    pub protocol: Protocol,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ports: Option<PortRange>,
    pub in_interface: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NatRule {
    pub action: Action,
    pub out_interface: Option<String>,
    pub src_subnet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub action: Action,
    pub interfaces: InterfaceMatch,
    pub state: Option<Vec<ConntrackState>>,
}

#[derive(Debug, Clone)]
pub struct IsolationRule {
    pub action: Action,
    pub interfaces: InterfaceMatch,
}
