Name:           sgx-guardian-client
Version:        1.0.0
Release:        1%{?dist}
Summary:        SGX Guardian Client - Zero-Trust Edge Security Agent

License:        Proprietary
URL:            https://github.com/AsadAli-CyberZeus/SGX
Source0:        sgx-guardian-client.tar.gz

ExclusiveArch:      x86_64
Requires:       systemd, ca-certificates

%description
SGX Guardian Client is a zero-trust edge security agent designed
to run on distributed nodes. It enforces signed security policies,
performs mutual attestation with trusted peers, establishes secure
mTLS channels, and maintains tamper-evident audit logs. The agent
operates autonomously and continues to function securely even when
disconnected from central infrastructure.

%prep
%setup -q -n sgx-guardian-client

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
mkdir -p %{buildroot}/etc/sgx-guardian
cp config/hostapd/hostapd.conf.template %{buildroot}/etc/sgx-guardian/
cp config/dnsmasq/dnsmasq.conf.template %{buildroot}/etc/sgx-guardian/
cp config/wpa_supplicant/wpa_supplicant.conf.template %{buildroot}/etc/sgx-guardian/

# ---- Scripts directory ----
mkdir -p %{buildroot}/usr/lib/sgx-guardian/scripts
cp scripts/check_ap_support.sh %{buildroot}/usr/lib/sgx-guardian/scripts/
chmod 755 %{buildroot}/usr/lib/sgx-guardian/scripts/*.sh

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
/etc/sgx-guardian/hostapd.conf.template
%dir %attr(0755,root,root) /usr/lib/sgx-guardian
%dir %attr(0755,root,root) /usr/lib/sgx-guardian/scripts
/usr/lib/sgx-guardian/scripts/check_ap_support.sh
%dir %attr(0755,root,root) /etc/sgx-guardian
%dir %attr(0750,sgxguardian,sgxguardian) /var/lib/sgx-guardian
%dir %attr(0750,sgxguardian,sgxguardian) /var/log/sgx-guardian

%changelog
* Sun Jan 18 2026 CyberZeus Security <security@cyberzeus.io> - 1.0.0-1
- Initial RPM package for SGX Guardian Client
