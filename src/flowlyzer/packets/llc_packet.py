

from .base_packet import BasePacket
from scapy.all import Packet
from typing import Dict, Any

class LLCPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_llc_features()

    def get_protocol_type(self) -> str:

        return 'LLC'

    def _extract_llc_features(self):

        try:
            if self.packet.haslayer('LLC'):
                llc_layer = self.packet['LLC']

                self.features['llc_dsap'] = int(llc_layer.dsap) if hasattr(llc_layer, 'dsap') else 0
                self.features['llc_ssap'] = int(llc_layer.ssap) if hasattr(llc_layer, 'ssap') else 0
                self.features['llc_ctrl'] = int(llc_layer.ctrl) if hasattr(llc_layer, 'ctrl') else 0
                self.features['llc_control'] = self.features['llc_ctrl']

                self.features['llc_dsap_sap'] = self.features['llc_dsap'] & 0xFE
                self.features['llc_ssap_sap'] = self.features['llc_ssap'] & 0xFE

                self.features['llc_dsap_cr'] = bool(self.features['llc_dsap'] & 0x01)
                self.features['llc_ssap_cr'] = bool(self.features['llc_ssap'] & 0x01)

                self.features['llc_dsap_ig'] = bool(self.features['llc_dsap'] & 0x01)

                ctrl = self.features['llc_ctrl']
                if (ctrl & 0x01) == 0:
                    self.features['llc_control_ftype'] = 0
                elif (ctrl & 0x03) == 0x01:
                    self.features['llc_control_ftype'] = 1
                else:
                    self.features['llc_control_ftype'] = 2

                    self.features['llc_control_u_modifier'] = (ctrl >> 2) & 0x1F
                null
                self.features['is_llc'] = True

            else:
                self.features['is_llc'] = False
                self._set_default_llc_features()

        except Exception:
            self.features['is_llc'] = False
            self._set_default_llc_features()

    def _set_default_llc_features(self):

        llc_defaults = {
            'llc_dsap': 0,
            'llc_ssap': 0,
            'llc_ctrl': 0,
            'llc_control': 0,
            'llc_dsap_sap': 0,
            'llc_ssap_sap': 0,
            'llc_dsap_cr': False,
            'llc_ssap_cr': False,
            'llc_dsap_ig': False,
            'llc_control_ftype': 0,
            'llc_control_u_modifier': 0,
        }
        self.features.update(llc_defaults)

class VTPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_vtp_features()

    def get_protocol_type(self) -> str:

        return 'VTP'

    def _extract_vtp_features(self):

        try:

            if self.packet.haslayer('LLC') and self.packet.haslayer('SNAP'):
                snap_layer = self.packet['SNAP']
                if hasattr(snap_layer, 'code') and snap_layer.code == 0x2003:
                    self.features['is_vtp'] = True

                    raw_payload = bytes(self.packet.payload) if self.packet.payload else b''
                    if len(raw_payload) >= 4:
                        self.features['vtp_version'] = raw_payload[0] if len(raw_payload) > 0 else 0
                        self.features['vtp_code'] = raw_payload[1] if len(raw_payload) > 1 else 0

                else:
                    self.features['is_vtp'] = False
                    self._set_default_vtp_features()
            else:
                self.features['is_vtp'] = False
                self._set_default_vtp_features()

        except Exception:
            self.features['is_vtp'] = False
            self._set_default_vtp_features()

    def _set_default_vtp_features(self):

        vtp_defaults = {
            'vtp_version': 0,
            'vtp_code': 0,
        }
        self.features.update(vtp_defaults)

class DTPPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_dtp_features()

    def get_protocol_type(self) -> str:

        return 'DTP'

    def _extract_dtp_features(self):

        try:

            self.features['is_dtp'] = True

            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''

            if len(raw_payload) >= 1:
                self.features['dtp_version'] = raw_payload[0]
            else:
                self.features['dtp_version'] = 0

            tlv_data = self._parse_dtp_tlvs(raw_payload)
            self.features['dtp_tlvs'] = tlv_data['tlv_count']

            self.features['dtp_tlv_len'] = tlv_data.get('domain_len', 0)
            self.features['dtp_trunk_status_tlv_len'] = tlv_data.get('trunk_status_len', 0)
            self.features['dtp_trunk_type_tlv_len'] = tlv_data.get('trunk_type_len', 0)
            self.features['dtp_sender_tlv_len'] = tlv_data.get('sender_id_len', 0)
            self.features['dtp_sender_id'] = tlv_data.get('sender_id', '')

        except Exception:
            self._set_default_dtp_features()

    def _parse_dtp_tlvs(self, payload: bytes) -> dict:

        tlv_data = {
            'tlv_count': 0,
            'domain_len': 0,
            'trunk_status_len': 0,
            'trunk_type_len': 0,
            'sender_id_len': 0,
            'sender_id': '',
        }

        try:
            offset = 1
            while offset < len(payload) - 4:
                if offset + 4 > len(payload):
                    break

                tlv_type = int.from_bytes(payload[offset:offset+2], 'big')
                tlv_length = int.from_bytes(payload[offset+2:offset+4], 'big')

                if tlv_length < 4 or offset + tlv_length > len(payload):
                    break

                tlv_data['tlv_count'] += 1

                tlv_value = payload[offset+4:offset+tlv_length]

                if tlv_type == 0x0001:
                    tlv_data['domain_len'] = tlv_length
                elif tlv_type == 0x0002:
                    tlv_data['trunk_status_len'] = tlv_length
                elif tlv_type == 0x0003:
                    tlv_data['trunk_type_len'] = tlv_length
                elif tlv_type == 0x0004:
                    tlv_data['sender_id_len'] = tlv_length
                    tlv_data['sender_id'] = tlv_value.decode('utf-8', errors='ignore')[:20]

                offset += tlv_length

        except Exception:
            pass

        return tlv_data

    def _set_default_dtp_features(self):

        dtp_defaults = {
            'dtp_version': 0,
            'dtp_tlvs': 0,
            'dtp_tlv_len': 0,
            'dtp_trunk_status_tlv_len': 0,
            'dtp_trunk_type_tlv_len': 0,
            'dtp_sender_tlv_len': 0,
            'dtp_sender_id': '',
        }
        self.features.update(dtp_defaults)

class ISLPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_isl_features()

    def get_protocol_type(self) -> str:

        return 'ISL'

    def _extract_isl_features(self):

        try:

            raw_data = bytes(self.packet)

            if len(raw_data) >= 26 and self._is_isl_frame(raw_data):
                self.features['is_isl'] = True

                if len(raw_data) >= 26:

                    self.features['isl_reserved'] = raw_data[4] if len(raw_data) > 4 else 0
                    self.features['isl_index'] = raw_data[5] if len(raw_data) > 5 else 0

                    vlan_bytes = raw_data[6:8] if len(raw_data) >= 8 else b'\x00\x00'
                    self.features['isl_vlan_id'] = int.from_bytes(vlan_bytes, 'big') & 0x0FFF

                    self.features['isl_len'] = len(self.packet)

                    self.features['isl_bpdu'] = 1 if b'\x42\x42' in raw_data[:30] else 0

                    self.features['isl_hsa'] = raw_data[8] if len(raw_data) > 8 else 0

                    encap_offset = 26
                    if len(raw_data) > encap_offset + 3:
                        self.features['isl_dsap'] = raw_data[encap_offset]
                        self.features['isl_ssap'] = raw_data[encap_offset + 1]
                        self.features['isl_control'] = raw_data[encap_offset + 2]
                    else:
                        self.features['isl_dsap'] = 0
                        self.features['isl_ssap'] = 0
                        self.features['isl_control'] = 0

                    self.features['isl_dst_type'] = (raw_data[0] >> 4) & 0x0F if len(raw_data) > 0 else 0
                    self.features['isl_dst_user_eth'] = raw_data[0] & 0x0F if len(raw_data) > 0 else 0

                else:
                    self._set_simplified_isl_features()

            else:
                self.features['is_isl'] = False
                self._set_default_isl_features()

        except Exception:
            self.features['is_isl'] = False
            self._set_default_isl_features()

    def _is_isl_frame(self, raw_data: bytes) -> bool:

        try:

            if len(raw_data) >= 26:

                return raw_data[0] & 0x01 == 0x01
            return False
        except Exception:
            return False

    def _set_simplified_isl_features(self):

        self.features['is_isl'] = True
        self.features['isl_len'] = len(self.packet)
        self.features['isl_bpdu'] = 0
        for field in ['isl_reserved', 'isl_index', 'isl_vlan_id', 'isl_hsa',
                     'isl_dsap', 'isl_ssap', 'isl_control', 'isl_dst_type', 'isl_dst_user_eth']:
            self.features[field] = 0

    def _set_default_isl_features(self):

        isl_defaults = {
            'isl_reserved': 0,
            'isl_index': 0,
            'isl_vlan_id': 0,
            'isl_len': 0,
            'isl_bpdu': 0,
            'isl_hsa': 0,
            'isl_dsap': 0,
            'isl_ssap': 0,
            'isl_control': 0,
            'isl_dst_type': 0,
            'isl_dst_user_eth': 0,
        }
        self.features.update(isl_defaults)

class LoopPacket(BasePacket):

    def __init__(self, scapy_packet: Packet, frame_number: int):
        super().__init__(scapy_packet, frame_number)
        self._extract_loop_features()

    def _extract_loop_features(self):

        try:

            raw_payload = bytes(self.packet.payload) if self.packet.payload else b''

            self.features['loop_skipcount'] = self._extract_skip_count(raw_payload)
            self.features['loop_receipt_number'] = self._extract_receipt_number(raw_payload)
            self.features['loop_function'] = self._extract_loop_function(raw_payload)
            self.features['loop_relevant_function'] = self._extract_relevant_function(raw_payload)

        except Exception:
            self._set_default_loop_features()

    def _extract_skip_count(self, payload: bytes) -> int:

        try:

            return len(payload) % 256 if payload else 0
        except Exception:
            return 0

    def _extract_receipt_number(self, payload: bytes) -> int:

        try:
            return (len(payload) // 10) % 1000 if payload else 0
        except Exception:
            return 0

    def _extract_loop_function(self, payload: bytes) -> int:

        try:
            return payload[0] if len(payload) > 0 else 0
        except Exception:
            return 0

    def _extract_relevant_function(self, payload: bytes) -> int:

        try:
            return payload[1] if len(payload) > 1 else 0
        except Exception:
            return 0

    def _set_default_loop_features(self):

        loop_defaults = {
            'loop_skipcount': 0,
            'loop_receipt_number': 0,
            'loop_function': 0,
            'loop_relevant_function': 0,
        }
        self.features.update(loop_defaults)