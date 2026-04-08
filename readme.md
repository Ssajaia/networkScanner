# scanNewtork

A PowerShell 7+ CLI tool for network scanning, ping checks, and TCP port enumeration with structured CSV/HTML reporting.

---

## Features

- Ping multiple hosts or subnets with parallel execution
- TCP port scanning for specified ports
- Subnet expansion via CIDR notation
- Filter results to online hosts only or open ports only
- Export reports in CSV or HTML format
- Colorized, timestamped console output
- Runspace-based parallel execution for large target lists

---

## Requirements

- PowerShell 7.0 or higher
- Windows, Linux, or macOS
- Elevated privileges may be required for ICMP ping on Linux/macOS

---

## Installation

```bash
git clone https://github.com/ssajaia/scanNewtork.git
cd scanNewtork
```

Or download `scanNewtork.ps1` directly from the repository.

---

## Usage

### Basic ping scan

```powershell
.\scanNewtork.ps1 -Target "192.168.1.1,192.168.1.5,192.168.1.10"
```

### Subnet scan with port checking

```powershell
.\scanNewtork.ps1 -Target "192.168.1.0/28" -Ports 22,80,443
```

### Export to CSV and HTML

```powershell
.\scanNewtork.ps1 -Target "192.168.1.0/28" -Ports 22,80,443 -ExportCSV "results.csv" -ExportHTML "results.html"
```

### Filter flags

```powershell
# Show online hosts only
.\scanNewtork.ps1 -Target "192.168.1.0/24" -OnlineOnly

# Show hosts with open ports only
.\scanNewtork.ps1 -Target "192.168.1.0/24" -Ports 22,80,443 -OpenPortsOnly
```

### Full example

```powershell
.\scanNewtork.ps1 -Target "192.168.1.0/24" -Ports 22,80,443 -ExportCSV "scan.csv" -OnlineOnly
```

---

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Target` | `string` | Comma-separated IPs or CIDR range (e.g. `192.168.1.0/24`) |
| `-Ports` | `int[]` | TCP ports to scan (e.g. `22,80,443`) |
| `-ExportCSV` | `string` | Output path for CSV report |
| `-ExportHTML` | `string` | Output path for HTML report |
| `-OnlineOnly` | `switch` | Only include reachable hosts in output |
| `-OpenPortsOnly` | `switch` | Only include hosts with at least one open port |

---

## Output

### Console

```
[12:45:10] Host 192.168.1.1 is online
[12:45:11] Port 80 on 192.168.1.1 is open
[12:45:12] Host 192.168.1.5 is offline
```

### HTML / CSV Report

| Host | Online | Open Ports |
|------|--------|------------|
| 192.168.1.1 | Yes | 22, 80, 443 |
| 192.168.1.2 | No | — |

---

## Notes

- Parallel execution uses PowerShell runspaces. Memory usage scales with the number of targets.
- ICMP ping may require `sudo` or running as Administrator on Linux/macOS.
- Tested on Windows 10/11 with PowerShell 7.3+.
- Only scan networks you own or have explicit permission to scan.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push the branch: `git push origin feature/my-feature`
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

**Saba Sajaia** — Computer Science Student  
[sabasajaia42@gmail.com](mailto:sabasajaia42@gmail.com) · [github.com/ssajaia](https://github.com/ssajaia)