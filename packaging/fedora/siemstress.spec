# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

Name:           siemstress
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightweight SIEM for homelabs

License:        GPL-3.0-or-later
URL:            https://github.com/Lezaford/siemstress
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  python3-pytest
BuildRequires:  openssl
Requires:       systemd

%description
SIEMstress collects logs from the systemd journal, syslog senders on the network,
log files and the Docker or Podman API; normalizes authentication, privilege,
account, audit and firewall events; raises alerts from detection rules tagged with
MITRE ATT&CK techniques; and provides a case workflow (disposition, actions taken,
activity log) for working them to a close. Single process, SQLite storage.

%package gui
Summary:        Desktop dashboard for SIEMstress
Requires:       %{name} = %{version}-%{release}
Requires:       python3-pyside6
Requires:       hicolor-icon-theme

%description gui
Qt desktop dashboard for SIEMstress, with tray notifications for new alerts.

%package tui
Summary:        Terminal dashboard for SIEMstress
Requires:       %{name} = %{version}-%{release}
Requires:       python3-textual

%description tui
Terminal dashboard for SIEMstress, usable over SSH on headless hosts.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files -l siemstress

install -Dpm0644 packaging/siemstress.service %{buildroot}%{_unitdir}/siemstress.service
install -Dpm0644 packaging/siemstress.sysusers %{buildroot}%{_sysusersdir}/siemstress.conf
install -Dpm0644 packaging/siemstress.tmpfiles %{buildroot}%{_tmpfilesdir}/siemstress.conf
install -Dpm0640 packaging/config.toml %{buildroot}%{_sysconfdir}/siemstress/config.toml
install -dm0750 %{buildroot}%{_sysconfdir}/siemstress/rules
install -Dpm0644 packaging/siemstress.1 %{buildroot}%{_mandir}/man1/siemstress.1
install -Dpm0644 contrib/config.example.toml %{buildroot}%{_docdir}/%{name}/config.example.toml

install -Dpm0644 packaging/siemstress.desktop %{buildroot}%{_datadir}/applications/siemstress.desktop
for size in 16 22 24 32 48 64 128 256; do
    install -Dpm0644 src/siemstress/assets/icon-$size.png \
        %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/siemstress.png
done
install -Dpm0644 src/siemstress/assets/icon.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/siemstress.svg

%check
%pytest -q

%post
%systemd_post siemstress.service

%preun
%systemd_preun siemstress.service

%postun
%systemd_postun_with_restart siemstress.service

%files -f %{pyproject_files}
%doc README.md docs/detection-coverage.md docs/alert-handling.md
%doc %{_docdir}/%{name}/config.example.toml
%{_bindir}/siemstress
%{_unitdir}/siemstress.service
%{_sysusersdir}/siemstress.conf
%{_tmpfilesdir}/siemstress.conf
%dir %attr(0750,root,siemstress) %{_sysconfdir}/siemstress
%dir %attr(0750,root,siemstress) %{_sysconfdir}/siemstress/rules
%config(noreplace) %attr(0640,root,siemstress) %{_sysconfdir}/siemstress/config.toml
%{_mandir}/man1/siemstress.1*

%files gui
%{_datadir}/applications/siemstress.desktop
%{_datadir}/icons/hicolor/*/apps/siemstress.*

%files tui

%changelog
* Wed Sep 23 2026 SIEMstress contributors <Lezaford@users.noreply.github.com> - 0.1.0-1
- Initial package
