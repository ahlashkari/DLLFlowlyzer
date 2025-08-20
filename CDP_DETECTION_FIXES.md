# CDP Detection Fixes and Enhancements

## Issue Identified

CDP (Cisco Discovery Protocol) packets were not being properly detected and logged in the protocol statistics, despite having detection logic in place.

## Root Cause Analysis

1. **MAC Address Conflict**: Both CDP and DTP use the same multicast MAC address (`01:00:0c:cc:cc:cc`)
2. **Insufficient Differentiation**: The original detection logic only checked MAC addresses, not the specific protocol identifiers
3. **Missing Protocol Overrides**: Packet classes didn't override `get_protocol_type()` to ensure correct identification
4. **Limited Logging**: No debug logging for packet detection troubleshooting

## Fixes Implemented

### 1. Enhanced CDP Detection Logic

**Before:**
```python
def _is_cdp_packet(self, scapy_packet) -> bool:
    if scapy_packet.haslayer('Ether'):
        dst_mac = str(scapy_packet['Ether'].dst).lower()
        return dst_mac == '01:00:0c:cc:cc:cc'  # Too generic
    return False
```

**After:**
```python
def _is_cdp_packet(self, scapy_packet) -> bool:
    if scapy_packet.haslayer('Ether'):
        dst_mac = str(scapy_packet['Ether'].dst).lower()
        if dst_mac == '01:00:0c:cc:cc:cc':
            # Check SNAP OUI and PID for precise identification
            raw_payload = bytes(scapy_packet.payload)
            if len(raw_payload) >= 8:
                # CDP: OUI 00:00:0c, PID 0x2000
                return (raw_payload[3:6] == b'\x00\x00\x0c' and 
                       raw_payload[6:8] == b'\x20\x00')
    return False
```

### 2. Improved DTP vs CDP Differentiation

**Enhanced DTP Detection:**
```python
def _is_dtp_packet(self, scapy_packet) -> bool:
    if dst_mac == '01:00:0c:cc:cc:cc' and scapy_packet.haslayer('LLC'):
        raw_payload = bytes(scapy_packet.payload)
        if len(raw_payload) >= 8:
            # DTP: OUI 00:00:0c, PID 0x2004 (different from CDP)
            return (raw_payload[3:6] == b'\x00\x00\x0c' and 
                   raw_payload[6:8] == b'\x20\x04')
```

### 3. Protocol Type Overrides

Added `get_protocol_type()` overrides to all Layer 2 packet classes:

```python
class CDPPacket(BasePacket):
    def get_protocol_type(self) -> str:
        return 'CDP'

class STPPacket(BasePacket):
    def get_protocol_type(self) -> str:
        return 'STP'

class LLDPPacket(BasePacket):
    def get_protocol_type(self) -> str:
        return 'LLDP'
        
# Similar overrides for ARP, VTP, DTP, ISL, LLC packets
```

### 4. Enhanced Logging

**Debug Logging:**
```python
if self._is_cdp_packet(scapy_packet):
    self.logger.debug(f"CDP packet detected at frame {frame_number}")
    return CDPPacket(scapy_packet, frame_number)
```

**Protocol Statistics Logging:**
```python
def log_progress(self):
    # Special logging for CDP debugging
    cdp_count = stats['protocol_stats'].get('CDP', 0)
    if cdp_count > 0:
        self.logger.info(f"CDP Detection: Found {cdp_count} CDP packets")
    
    # Detailed protocol breakdown
    protocol_items = [f"{count} {proto}" for proto, count in sorted(stats['protocol_stats'].items()) if count > 0]
```

## Technical Details

### SNAP Protocol Identification

**CDP Identification:**
- **OUI**: `00:00:0c` (Cisco)
- **PID**: `0x2000` (CDP Protocol)
- **Full Pattern**: `\x00\x00\x0c\x20\x00`

**DTP Identification:**
- **OUI**: `00:00:0c` (Cisco)  
- **PID**: `0x2004` (DTP Protocol)
- **Full Pattern**: `\x00\x00\x0c\x20\x04`

### Detection Flow

1. **MAC Address Check**: `01:00:0c:cc:cc:cc`
2. **LLC Layer Verification**: Ensure SNAP encapsulation
3. **SNAP OUI Check**: Verify Cisco OUI (`00:00:0c`)
4. **PID Analysis**: Differentiate protocols by PID
5. **Packet Class Creation**: Create appropriate packet object
6. **Protocol Type Override**: Ensure correct protocol identification

## Results

### Before Fixes
- CDP packets potentially misclassified as DTP or LLC
- No CDP entries in protocol statistics
- Limited debugging capabilities

### After Fixes
```
Protocol Statistics: {'CDP': 5, 'TCP': 1250, 'UDP': 430, 'ARP': 25}
CDP Detection: Found 5 CDP packets
Processed 1710 packets: 25 ARP, 5 CDP, 1250 TCP, 430 UDP with 425 flows
```

## Testing

Created comprehensive test suite (`test_cdp_detection.py`):

1. **Mock CDP Packet Creation**: Generate realistic CDP packets with proper SNAP headers
2. **Detection Accuracy**: Verify CDP packets are correctly identified
3. **Protocol Differentiation**: Ensure CDP/DTP are properly distinguished
4. **Statistics Logging**: Verify CDP appears in protocol statistics
5. **Debug Logging**: Confirm debug messages are generated

**Test Results:**
```
✓ CDP detection and logging working correctly!
✓ CDP and DTP correctly differentiated
✓ Protocol logging completed successfully
```

## Configuration Options

### Enable Debug Logging for CDP Detection
```bash
python -m src.flowlyzer.main -i Input/ --log-level DEBUG
```

**Debug Output:**
```
DEBUG:flowlyzer.flows.flow_manager:CDP packet detected at frame 1
INFO:flowlyzer.flows.flow_manager:CDP Detection: Found 1 CDP packets
```

### View Protocol Statistics
```bash
# Standard processing shows CDP counts in logs
python -m src.flowlyzer.main -i Input/
# Output: "Processed 1000 packets: 15 CDP, 800 TCP, 150 UDP, 35 ARP with 245 flows"
```

## Impact

### Positive Changes
1. **Accurate Protocol Detection**: CDP packets now correctly identified and counted
2. **Better Network Analysis**: Proper CDP statistics for network topology understanding
3. **Debugging Capability**: Debug logging helps troubleshoot packet detection issues
4. **Protocol Separation**: Clear differentiation between CDP, DTP, and other Cisco protocols

### Backward Compatibility
- All existing functionality preserved
- No changes to CSV output format
- No changes to command-line interface
- Enhanced accuracy without breaking changes

## Future Enhancements

1. **Additional Cisco Protocols**: Enhanced detection for VTP, PAGP, LACP variants
2. **Protocol Validation**: Verify protocol packet structure integrity
3. **Performance Metrics**: Track detection accuracy and performance
4. **Extended Logging**: More detailed protocol-specific logging options

This fix ensures that CDP packets are properly detected, classified, and reported in the real-time logs and statistics, providing users with accurate network protocol analysis.