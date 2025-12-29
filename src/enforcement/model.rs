//! Internal enforcement rule model.
//!
//! This is an OS-agnostic representation of firewall intent.

#![allow(dead_code)]

#[derive(Debug, Clone)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct EnforcementRule {
    pub action: Action,
    pub protocol: Protocol,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ports: Option<PortRange>,
}
