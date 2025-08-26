# Layer 2 Attack Labeling Configuration Files

This directory contains comprehensive labeling configuration files for different Layer 2 attack types based on your attacks.txt timeline. Each file is designed to work with the DLL Flowlyzer's labeling system.

## Quick Start

1. **Choose the appropriate labeling file** for your attack folder
2. **Replace placeholder values** with actual attacker MAC/IP addresses
3. **Run DLL Flowlyzer** with the `--label-config` parameter

```bash
# Example usage
python -m src.flowlyzer.main -i /path/to/vlan_attack_folder --label-config labels/vlan_attack_labels.json --separate-layers
```

## Configuration Files Overview

| Attack Type | File | Layer 2 Only | Key Protocols |
|-------------|------|--------------|---------------|
| VLAN Attack | `vlan_attack_labels.json` | ✅ Yes | DTP, VTP, VLAN |
| Impersonation | `impersonation_attack_labels.json` | ✅ Yes | ARP, CDP, DHCP |
| DHCP Spoofing | `dhcp_spoof_attack_labels.json` | ❌ No | DHCP, ARP, UDP |
| CDP Attack | `cdp_attack_labels.json` | ✅ Yes | CDP, LLC, SNAP |
| CAM Table Flood | `cam_table_flood_labels.json` | ✅ Yes | ETH, ARP |
| STP Attack | `stp_attack_labels.json` | ✅ Yes | STP, BPDU, RSTP |
| DHCP Starvation | `dhcp_starvation_labels.json` | ❌ No | DHCP, ARP, UDP |
| ARP Spoofing | `arp_spoof_labels.json` | ✅ Yes | ARP |
| ARP Poisoning | `arp_poisoning_labels.json` | ✅ Yes | ARP |
| Switch Spoofing | `switch_spoof_labels.json` | ✅ Yes | STP, CDP, DTP |
| Switch Spoofing 2 | `switch_spoof2_labels.json` | ✅ Yes | STP, CDP, VTP |
| ARP Spoofing 2 | `arp_spoof2_labels.json` | ✅ Yes | ARP |

## Key Features

### 1. Layer 2 Only Option
```json
"layer_2_only": true
```
- **true**: Apply labels only to Layer 2 flows (recommended for most attacks)
- **false**: Apply labels to all flows (use for attacks affecting L2 and L3)

### 2. Protocol-Specific Labeling
```json
"protocol_specific_labels": [
    {
        "protocols": ["ARP", "CDP"],
        "time_range": "10:50-15:23", 
        "label": "Targeted Protocol Attack",
        "description": "Attack targeting specific protocols"
    }
]
```

### 3. Recurring Attack Patterns
```json
"recurring_pattern": {
    "start_time": "11:12",
    "end_time": "17:00",
    "interval_minutes": 2,
    "attack_duration_seconds": 30
}
```

## Required Customization

### 1. Replace IP Placeholders
```json
"ip_labels": [
    {
        "ip": "192.168.1.100",  // Replace ATTACKER_IP_PLACEHOLDER
        "label": "Attacker Device"
    }
]
```

### 2. Replace MAC Placeholders  
```json
"mac_labels": [
    {
        "mac": "aa:bb:cc:dd:ee:ff",  // Replace ATTACKER_MAC_PLACEHOLDER
        "label": "Attacker Device"
    }
]
```

## Usage Examples

### Basic Usage
```bash
# Label VLAN attack data
python -m src.flowlyzer.main -i vlan_attack_data/ --label-config labels/vlan_attack_labels.json --separate-layers

# Label with specific attacker IP
python -m src.flowlyzer.main -i cdp_attack_data/ --label-config labels/cdp_attack_labels.json --label-ip "192.168.1.50=CDP Attacker"
```

### Advanced Usage with Multiple Labels
```bash
# Combine time-based and MAC-based labeling
python -m src.flowlyzer.main -i arp_spoof_data/ \
    --label-config labels/arp_spoof_labels.json \
    --label-mac "aa:bb:cc:dd:ee:ff=ARP Attacker" \
    --label-ip "192.168.1.100=ARP Target" \
    --separate-layers
```

## Time Format

All time ranges use HH:MM format (24-hour):
- `"10:43-10:55"` = 10:43 AM to 10:55 AM  
- `"14:20-14:41"` = 2:20 PM to 2:41 PM

## Attack Timeline Summary

### Early Morning (10:00-11:00)
- ARP Spoof 2 (10:09-10:40)
- Switch Spoof (10:20-10:30) 
- DHCP Starvation (10:43-10:55)
- Switch Spoof 2 (10:48-10:58)
- STP Attack (10:50-11:00)
- Impersonation (10:53-11:00)
- CDP Attack (10:57-11:00)
- CAM Flood (10:59-11:00)

### Recurring Patterns
- **VLAN Attack**: Every 2 minutes from 11:12-17:00
- **ARP Poisoning**: Every 2 minutes from 11:12-17:00  
- **Switch Spoof**: Every 30 minutes from 10:20-17:00
- **Switch Spoof 2**: Every 30 minutes from 10:48-17:00

## Protocol-Specific Notes

### ARP-Based Attacks
- Focus on gratuitous ARP packets
- Monitor IP-MAC binding conflicts
- Track ARP reply rates

### DHCP Attacks  
- Monitor ports 67/68 UDP traffic
- Track DHCP message types (DISCOVER, REQUEST, OFFER)
- Watch for IP pool exhaustion

### STP/CDP Attacks
- Focus on BPDU manipulation 
- Monitor bridge priority values
- Track topology change notifications

## Troubleshooting

### Common Issues
1. **No labels applied**: Check time format and ensure attack time falls within PCAP timeframe
2. **Wrong protocol labeled**: Verify `layer_2_only` setting matches your attack type
3. **Missing attacker identification**: Replace placeholder MAC/IP values

### Validation
```bash
# Test labeling configuration
python -m src.flowlyzer.main -i test_data/ --label-config labels/your_attack_labels.json --log-level DEBUG
```

## Contact
For questions about these labeling configurations, refer to the main project documentation or attack analysis reports.