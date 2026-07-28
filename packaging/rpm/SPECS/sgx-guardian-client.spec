Name:           sgx-guardian-client
Version:        %{?version_override}%{!?version_override:0.0.0}
Release:        1%{?dist}
Summary:        SGX Guardian Client - Zero-Trust Edge Security Agent

License:        Proprietary
URL:            https://github.com/Cervais/new-guardian
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:      x86_64
Requires:       systemd, ca-certificates, nmap, libcap

%description
SGX Guardian Client is a zero-trust edge security agent designed
to run on distributed nodes. It enforces signed security policies,
performs mutual attestation with trusted peers, establishes secure
mTLS channels, and maintains tamper-evident audit logs. The agent
operates autonomously and continues to function securely even when
disconnected from central infrastructure.

%prep
%setup -q

%build
# No build required (pre-built Rust binary)

%install
rm -rf %{buildroot}

# ---- Binary ----
mkdir -p %{buildroot}/usr/bin
cp sgx-guardian %{buildroot}/usr/bin/sgx-guardian
chmod 755 %{buildroot}/usr/bin/sgx-guardian

# ---- systemd service ----
mkdir -p %{buildroot}/lib/systemd/system
cp sgx-guardian.service %{buildroot}/lib/systemd/system/

# ---- Config directory ----
mkdir -p %{buildroot}/etc/sgx-guardian/config
cp -a config/node*.yaml %{buildroot}/etc/sgx-guardian/config/
cp -a config/node_profile %{buildroot}/etc/sgx-guardian/
mkdir -p %{buildroot}/etc/sgx-guardian/policies
cp -a policies/. %{buildroot}/etc/sgx-guardian/policies/

# ---- Runtime directories (empty) ----
mkdir -p %{buildroot}/var/lib/sgx-guardian
mkdir -p %{buildroot}/var/log/sgx-guardian

%pre
# Create system group if not exists
getent group sgxguardian >/dev/null || groupadd -r sgxguardian

# Create system user if not exists
getent passwd sgxguardian >/dev/null || \
useradd -r -g sgxguardian -d /var/lib/sgx-guardian -s /sbin/nologin sgxguardian

exit 0

%post
# Keep nmap privileges scoped in systemd unit; do not set file capabilities on /usr/bin/nmap.

# systemd reload & enable (no auto-start)
if command -v systemctl >/dev/null; then
    systemctl daemon-reload
    systemctl enable sgx-guardian.service >/dev/null || true
fi
exit 0

%preun
# Stop & disable service on removal
if [ $1 -eq 0 ]; then
    if command -v systemctl >/dev/null; then
        systemctl stop sgx-guardian.service >/dev/null || true
        systemctl disable sgx-guardian.service >/dev/null || true
        systemctl daemon-reload
    fi
fi
exit 0

%postun
# Final daemon reload
if command -v systemctl >/dev/null; then
    systemctl daemon-reload
fi
exit 0

%files
/usr/bin/sgx-guardian
/lib/systemd/system/sgx-guardian.service
%dir %attr(0755,root,root) /etc/sgx-guardian
%config(noreplace) /etc/sgx-guardian/node_profile
%dir /etc/sgx-guardian/config
%config(noreplace) /etc/sgx-guardian/config/nodeA.yaml
%config(noreplace) /etc/sgx-guardian/config/nodeB.yaml
%config(noreplace) /etc/sgx-guardian/config/nodeC.yaml
%dir /etc/sgx-guardian/policies
%config(noreplace) /etc/sgx-guardian/policies/active_policy.yaml
%config(noreplace) /etc/sgx-guardian/policies/backup_policy.yaml
%dir %attr(0750,sgxguardian,sgxguardian) /var/lib/sgx-guardian
%dir %attr(0750,sgxguardian,sgxguardian) /var/log/sgx-guardian

%changelog
* Sun Jan 18 2026 CyberZeus Security <security@cyberzeus.io> - 1.0.0-1
- Initial RPM package for SGX Guardian Client
