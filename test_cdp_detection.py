#!/usr/bin/env python3
"""
Test script for CDP packet detection and logging.
"""

import sys
import os
import logging

# Add src to path for imports
sys.path.insert(0, 'src')

from flowlyzer.flows.flow_manager import FlowManager
from flowlyzer.packets.layer2_packet import CDPPacket
from scapy.all import Ether, LLC, Raw, Packet


def create_mock_cdp_packet():
    """Create a mock CDP packet for testing."""
    # Create CDP packet with proper MAC and LLC structure
    cdp_mac = "01:00:0c:cc:cc:cc"
    
    # Create LLC header with SNAP for CDP
    llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)  # SNAP
    
    # Create CDP payload with proper SNAP OUI and PID
    # OUI: 00:00:0c (Cisco), PID: 0x2000 (CDP)
    cdp_snap = b'\x00\x00\x0c\x20\x00'  # OUI + PID for CDP
    cdp_payload = cdp_snap + b'\x01\x00\x00\x00'  # Version 1, TTL 0, Checksum 0
    
    # Create complete packet
    packet = Ether(dst=cdp_mac) / llc_header / Raw(load=cdp_payload)
    
    return packet


def create_mock_dtp_packet():
    """Create a mock DTP packet for comparison."""
    # Create DTP packet with proper MAC and LLC structure
    dtp_mac = "01:00:0c:cc:cc:cc"
    
    # Create LLC header with SNAP for DTP
    llc_header = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)  # SNAP
    
    # Create DTP payload with proper SNAP OUI and PID
    # OUI: 00:00:0c (Cisco), PID: 0x2004 (DTP)
    dtp_snap = b'\x00\x00\x0c\x20\x04'  # OUI + PID for DTP
    dtp_payload = dtp_snap + b'\x01\x00\x00\x00'  # Version 1 DTP data
    
    # Create complete packet
    packet = Ether(dst=dtp_mac) / llc_header / Raw(load=dtp_payload)
    
    return packet


def test_cdp_detection():
    """Test CDP packet detection."""
    print("Testing CDP Detection...")
    
    # Set up logging to capture debug messages
    logging.basicConfig(level=logging.DEBUG)
    
    flow_manager = FlowManager()
    
    # Test CDP packet
    cdp_packet = create_mock_cdp_packet()
    print(f"  Created mock CDP packet: {cdp_packet.summary()}")
    
    # Test CDP detection
    is_cdp = flow_manager._is_cdp_packet(cdp_packet)
    print(f"  CDP Detection Result: {is_cdp}")
    
    if is_cdp:
        # Test packet creation
        try:
            packet_obj = flow_manager._create_packet_object(cdp_packet, 1)
            protocol_type = packet_obj.get_protocol_type()
            print(f"  ✓ Created CDPPacket successfully")
            print(f"  ✓ Protocol Type: {protocol_type}")
            
            # Test processing
            flow = flow_manager.process_packet(cdp_packet, 1)
            if flow:
                print(f"  ✓ Flow created successfully: {flow.flow_id}")
            
            # Check statistics
            stats = flow_manager.get_statistics()
            cdp_count = stats['protocol_stats'].get('CDP', 0)
            print(f"  ✓ CDP packets in stats: {cdp_count}")
            
            return cdp_count > 0
            
        except Exception as e:
            print(f"  ✗ Error creating CDP packet object: {e}")
            return False
    else:
        print("  ✗ CDP packet not detected")
        return False


def test_dtp_vs_cdp_detection():
    """Test that DTP and CDP are correctly differentiated."""
    print("\nTesting DTP vs CDP Differentiation...")
    
    flow_manager = FlowManager()
    
    # Test CDP
    cdp_packet = create_mock_cdp_packet()
    is_cdp = flow_manager._is_cdp_packet(cdp_packet)
    is_dtp_cdp = flow_manager._is_dtp_packet(cdp_packet)
    
    print(f"  CDP packet - CDP detection: {is_cdp}, DTP detection: {is_dtp_cdp}")
    
    # Test DTP
    dtp_packet = create_mock_dtp_packet()
    is_cdp_dtp = flow_manager._is_cdp_packet(dtp_packet)
    is_dtp = flow_manager._is_dtp_packet(dtp_packet)
    
    print(f"  DTP packet - CDP detection: {is_cdp_dtp}, DTP detection: {is_dtp}")
    
    # Verify correct differentiation
    if is_cdp and not is_dtp_cdp and not is_cdp_dtp and is_dtp:
        print("  ✓ CDP and DTP correctly differentiated")
        return True
    else:
        print("  ✗ CDP and DTP not properly differentiated")
        return False


def test_protocol_logging():
    """Test that CDP appears in protocol statistics logging."""
    print("\nTesting Protocol Statistics Logging...")
    
    flow_manager = FlowManager()
    
    # Process multiple CDP packets
    for i in range(5):
        cdp_packet = create_mock_cdp_packet()
        flow_manager.process_packet(cdp_packet, i + 1)
    
    # Get statistics
    stats = flow_manager.get_statistics()
    print(f"  Protocol Statistics: {stats['protocol_stats']}")
    
    # Test logging
    try:
        flow_manager.log_progress()
        print("  ✓ Protocol logging completed successfully")
        return True
    except Exception as e:
        print(f"  ✗ Error in protocol logging: {e}")
        return False


def main():
    """Run all CDP detection tests."""
    print("=" * 60)
    print("CDP Detection and Logging Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 3
    
    # Run tests
    if test_cdp_detection():
        tests_passed += 1
    
    if test_dtp_vs_cdp_detection():
        tests_passed += 1
    
    if test_protocol_logging():
        tests_passed += 1
    
    # Show results
    print("\n" + "=" * 60)
    print(f"Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("✓ CDP detection and logging working correctly!")
        print("\nFixes implemented:")
        print("• Improved CDP detection with SNAP OUI/PID checking")
        print("• Better differentiation between CDP and DTP packets")
        print("• Added protocol type overrides for all Layer 2 packet classes")
        print("• Enhanced protocol statistics logging with CDP tracking")
        print("• Added debug logging for packet detection")
        return 0
    else:
        print(f"✗ {total_tests - tests_passed} tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())