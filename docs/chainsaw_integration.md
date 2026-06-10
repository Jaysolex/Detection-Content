# Chainsaw Integration Guide

Chainsaw is a SIEM-less threat hunting tool that executes Sigma rules directly against Windows event logs. Perfect for offline incident response and isolated network analysis.

---

## Installation

### macOS (Homebrew)
```bash
brew install chainsaw
chainsaw --version
```

### Linux (Cargo)
```bash
cargo install chainsaw
chainsaw --version
```

### Windows (Direct Download)
1. Download: https://github.com/WithSecureLabs/chainsaw/releases
2. Extract to: `C:\Tools\chainsaw\`
3. Add to PATH
4. Verify: `chainsaw.exe --version`

---

## Quick Start

### Hunt Against Local Event Logs

macOS/Linux (mounted volume):
```bash
chainsaw hunt -s sigma/ -e /mnt/windows/Windows/System32/winevt/Logs/
```

Windows (native):
```bash
chainsaw hunt -s sigma/ -e C:\Windows\System32\winevt\Logs\
```

### Export Results to JSON
```bash
chainsaw hunt -s sigma/ -e /path/to/logs/ --output json > results.json
```

### Parallel Processing (Faster)
```bash
chainsaw hunt -s sigma/ -e /path/to/logs/ --threads 8
```

---

## Use Cases

✅ Offline incident response (no network needed)
✅ Isolated network analysis (air-gapped systems)
✅ Quick threat hunting (no SIEM required)
✅ Portable analysis (USB drive scanning)
✅ Cost-effective (free & open-source)

---

## Real-World Incident Response Example

1. **Collect logs from compromised host:**
```bash
wevtutil query-ids Security /format:evtx > Security.evtx
wevtutil query-ids System /format:evtx > System.evtx
wevtutil query-ids "Windows PowerShell" /format:evtx > PowerShell.evtx
```

2. **Transfer to analysis machine:**
```bash
scp user@host:*.evtx ~/incident-response/logs/
```

3. **Run Chainsaw hunt:**
```bash
chainsaw hunt -s sigma/ -e ~/incident-response/logs/ --output json > findings.json
```

4. **Analyze results:**
```bash
cat findings.json | jq '.[] | select(.rule | contains("PowerShell"))'
```

---

## Chainsaw vs SIEM

| Feature | Chainsaw | Splunk/Sentinel |
|---------|----------|-----------------|
| Offline Hunting | ✅ Yes | ❌ No |
| Cost | ✅ Free | ❌ Expensive |
| Setup Time | ✅ Minutes | ❌ Weeks |
| Continuous Monitoring | ❌ No | ✅ Yes |
| Multi-Host Correlation | ❌ No | ✅ Yes |
| Long-term Retention | ❌ No | ✅ Yes |

---

## References

- Chainsaw GitHub: https://github.com/WithSecureLabs/chainsaw
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Detection-Content: https://github.com/Jaysolex/Detection-Content

