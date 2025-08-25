"""
Flow manager for tracking and managing network flows.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

from .flow import Flow
from ..packets.base_packet import BasePacket
from ..packets.tcp_packet import TCPPacket
from ..packets.udp_packet import UDPPacket
from ..packets.layer2_packet import STPPacket, CDPPacket, LLDPPacket, ARPPacket
from ..packets.llc_packet import LLCPacket, VTPPacket, DTPPacket, ISLPacket, LoopPacket


_CISCO_MACS= ["00:00:0c:cc:cc:cc","00:01:42:cc:cc:cc","00:01:43:cc:cc:cc","00:01:63:cc:cc:cc","00:01:64:cc:cc:cc","00:01:96:cc:cc:cc","00:01:97:cc:cc:cc","00:01:c7:cc:cc:cc","00:01:c9:cc:cc:cc","00:02:16:cc:cc:cc","00:02:17:cc:cc:cc","00:02:3d:cc:cc:cc","00:02:4a:cc:cc:cc","00:02:4b:cc:cc:cc","00:02:7d:cc:cc:cc","00:02:7e:cc:cc:cc","00:02:b9:cc:cc:cc","00:02:ba:cc:cc:cc","00:02:fc:cc:cc:cc","00:02:fd:cc:cc:cc","00:03:31:cc:cc:cc","00:03:32:cc:cc:cc","00:03:6b:cc:cc:cc","00:03:6c:cc:cc:cc","00:03:9f:cc:cc:cc","00:03:a0:cc:cc:cc","00:03:e3:cc:cc:cc","00:03:e4:cc:cc:cc","00:03:fd:cc:cc:cc","00:03:fe:cc:cc:cc","00:04:27:cc:cc:cc","00:04:28:cc:cc:cc","00:04:4d:cc:cc:cc","00:04:4e:cc:cc:cc","00:04:6d:cc:cc:cc","00:04:6e:cc:cc:cc","00:04:9a:cc:cc:cc","00:04:9b:cc:cc:cc","00:04:c0:cc:cc:cc","00:04:c1:cc:cc:cc","00:04:dd:cc:cc:cc","00:04:de:cc:cc:cc","00:05:00:cc:cc:cc","00:05:01:cc:cc:cc","00:05:31:cc:cc:cc","00:05:32:cc:cc:cc","00:05:5e:cc:cc:cc","00:05:5f:cc:cc:cc","00:05:73:cc:cc:cc","00:05:74:cc:cc:cc","00:05:9a:cc:cc:cc","00:05:9b:cc:cc:cc","00:05:dc:cc:cc:cc","00:05:dd:cc:cc:cc","00:06:28:cc:cc:cc","00:06:2a:cc:cc:cc","00:06:52:cc:cc:cc","00:06:53:cc:cc:cc","00:06:7c:cc:cc:cc","00:06:c1:cc:cc:cc","00:06:d6:cc:cc:cc","00:06:d7:cc:cc:cc","00:06:f6:cc:cc:cc","00:07:0d:cc:cc:cc","00:07:0e:cc:cc:cc","00:07:4f:cc:cc:cc","00:07:50:cc:cc:cc","00:07:7d:cc:cc:cc","00:07:84:cc:cc:cc","00:07:85:cc:cc:cc","00:07:b3:cc:cc:cc","00:07:b4:cc:cc:cc","00:07:eb:cc:cc:cc","00:07:ec:cc:cc:cc","00:08:20:cc:cc:cc","00:08:21:cc:cc:cc","00:08:2f:cc:cc:cc","00:08:30:cc:cc:cc","00:08:31:cc:cc:cc","00:08:32:cc:cc:cc","00:08:7c:cc:cc:cc","00:08:7d:cc:cc:cc","00:08:a3:cc:cc:cc","00:08:a4:cc:cc:cc","00:08:c2:cc:cc:cc","00:08:e2:cc:cc:cc","00:08:e3:cc:cc:cc","00:09:11:cc:cc:cc","00:09:12:cc:cc:cc","00:09:43:cc:cc:cc","00:09:44:cc:cc:cc","00:09:7b:cc:cc:cc","00:09:7c:cc:cc:cc","00:09:b6:cc:cc:cc","00:09:b7:cc:cc:cc","00:09:e8:cc:cc:cc","00:09:e9:cc:cc:cc","00:0a:41:cc:cc:cc","00:0a:42:cc:cc:cc","00:0a:8a:cc:cc:cc","00:0a:8b:cc:cc:cc","00:0a:b7:cc:cc:cc","00:0a:b8:cc:cc:cc","00:0a:f3:cc:cc:cc","00:0a:f4:cc:cc:cc","00:0b:45:cc:cc:cc","00:0b:46:cc:cc:cc","00:0b:5f:cc:cc:cc","00:0b:60:cc:cc:cc","00:0b:85:cc:cc:cc","00:0b:be:cc:cc:cc","00:0b:bf:cc:cc:cc","00:0b:fc:cc:cc:cc","00:0b:fd:cc:cc:cc","00:0c:30:cc:cc:cc","00:0c:31:cc:cc:cc","00:0c:41:cc:cc:cc","00:0c:85:cc:cc:cc","00:0c:86:cc:cc:cc","00:0c:ce:cc:cc:cc","00:0c:cf:cc:cc:cc","00:0d:28:cc:cc:cc","00:0d:29:cc:cc:cc","00:0d:65:cc:cc:cc","00:0d:66:cc:cc:cc","00:0d:bc:cc:cc:cc","00:0d:bd:cc:cc:cc","00:0d:ec:cc:cc:cc","00:0d:ed:cc:cc:cc","00:0e:08:cc:cc:cc","00:0e:38:cc:cc:cc","00:0e:39:cc:cc:cc","00:0e:83:cc:cc:cc","00:0e:84:cc:cc:cc","00:0e:d6:cc:cc:cc","00:0e:d7:cc:cc:cc","00:0f:23:cc:cc:cc","00:0f:24:cc:cc:cc","00:0f:34:cc:cc:cc","00:0f:35:cc:cc:cc","00:0f:66:cc:cc:cc","00:0f:8f:cc:cc:cc","00:0f:90:cc:cc:cc","00:0f:f7:cc:cc:cc","00:0f:f8:cc:cc:cc","00:10:07:cc:cc:cc","00:10:0b:cc:cc:cc","00:10:0d:cc:cc:cc","00:10:11:cc:cc:cc","00:10:14:cc:cc:cc","00:10:1f:cc:cc:cc","00:10:29:cc:cc:cc","00:10:2f:cc:cc:cc","00:10:54:cc:cc:cc","00:10:79:cc:cc:cc","00:10:7b:cc:cc:cc","00:10:a6:cc:cc:cc","00:10:f6:cc:cc:cc","00:10:ff:cc:cc:cc","00:11:20:cc:cc:cc","00:11:21:cc:cc:cc","00:11:5c:cc:cc:cc","00:11:5d:cc:cc:cc","00:11:92:cc:cc:cc","00:11:93:cc:cc:cc","00:11:bb:cc:cc:cc","00:11:bc:cc:cc:cc","00:12:00:cc:cc:cc","00:12:01:cc:cc:cc","00:12:17:cc:cc:cc","00:12:43:cc:cc:cc","00:12:44:cc:cc:cc","00:12:7f:cc:cc:cc","00:12:80:cc:cc:cc","00:12:d9:cc:cc:cc","00:12:da:cc:cc:cc","00:13:10:cc:cc:cc","00:13:19:cc:cc:cc","00:13:1a:cc:cc:cc","00:13:5f:cc:cc:cc","00:13:60:cc:cc:cc","00:13:7f:cc:cc:cc","00:13:80:cc:cc:cc","00:13:c3:cc:cc:cc","00:13:c4:cc:cc:cc","00:14:1b:cc:cc:cc","00:14:1c:cc:cc:cc","00:14:69:cc:cc:cc","00:14:6a:cc:cc:cc","00:14:a8:cc:cc:cc","00:14:a9:cc:cc:cc","00:14:bf:cc:cc:cc","00:14:f1:cc:cc:cc","00:14:f2:cc:cc:cc","00:15:2b:cc:cc:cc","00:15:2c:cc:cc:cc","00:15:62:cc:cc:cc","00:15:63:cc:cc:cc","00:15:c6:cc:cc:cc","00:15:c7:cc:cc:cc","00:15:f9:cc:cc:cc","00:15:fa:cc:cc:cc","00:16:46:cc:cc:cc","00:16:47:cc:cc:cc","00:16:9c:cc:cc:cc","00:16:9d:cc:cc:cc","00:16:b6:cc:cc:cc","00:16:c7:cc:cc:cc","00:16:c8:cc:cc:cc","00:17:0e:cc:cc:cc","00:17:0f:cc:cc:cc","00:17:3b:cc:cc:cc","00:17:59:cc:cc:cc","00:17:5a:cc:cc:cc","00:17:94:cc:cc:cc","00:17:95:cc:cc:cc","00:17:df:cc:cc:cc","00:17:e0:cc:cc:cc","00:18:18:cc:cc:cc","00:18:19:cc:cc:cc","00:18:39:cc:cc:cc","00:18:68:cc:cc:cc","00:18:73:cc:cc:cc","00:18:74:cc:cc:cc","00:18:b9:cc:cc:cc","00:18:ba:cc:cc:cc","00:18:f8:cc:cc:cc","00:19:06:cc:cc:cc","00:19:07:cc:cc:cc","00:19:2f:cc:cc:cc","00:19:30:cc:cc:cc","00:19:47:cc:cc:cc","00:19:55:cc:cc:cc","00:19:56:cc:cc:cc","00:19:a9:cc:cc:cc","00:19:aa:cc:cc:cc","00:19:e7:cc:cc:cc","00:19:e8:cc:cc:cc","00:1a:2f:cc:cc:cc","00:1a:30:cc:cc:cc","00:1a:6c:cc:cc:cc","00:1a:6d:cc:cc:cc","00:1a:70:cc:cc:cc","00:1a:a1:cc:cc:cc","00:1a:a2:cc:cc:cc","00:1a:e2:cc:cc:cc","00:1a:e3:cc:cc:cc","00:1b:0c:cc:cc:cc","00:1b:0d:cc:cc:cc","00:1b:2a:cc:cc:cc","00:1b:2b:cc:cc:cc","00:1b:53:cc:cc:cc","00:1b:54:cc:cc:cc","00:1b:67:cc:cc:cc","00:1b:8f:cc:cc:cc","00:1b:90:cc:cc:cc","00:1b:d4:cc:cc:cc","00:1b:d5:cc:cc:cc","00:1b:d7:cc:cc:cc","00:1c:0e:cc:cc:cc","00:1c:0f:cc:cc:cc","00:1c:10:cc:cc:cc","00:1c:57:cc:cc:cc","00:1c:58:cc:cc:cc","00:1c:b0:cc:cc:cc","00:1c:b1:cc:cc:cc","00:1c:f6:cc:cc:cc","00:1c:f9:cc:cc:cc","00:1d:45:cc:cc:cc","00:1d:46:cc:cc:cc","00:1d:70:cc:cc:cc","00:1d:71:cc:cc:cc","00:1d:7e:cc:cc:cc","00:1d:a1:cc:cc:cc","00:1d:a2:cc:cc:cc","00:1d:e5:cc:cc:cc","00:1d:e6:cc:cc:cc","00:1e:13:cc:cc:cc","00:1e:14:cc:cc:cc","00:1e:49:cc:cc:cc","00:1e:4a:cc:cc:cc","00:1e:6b:cc:cc:cc","00:1e:79:cc:cc:cc","00:1e:7a:cc:cc:cc","00:1e:bd:cc:cc:cc","00:1e:be:cc:cc:cc","00:1e:e5:cc:cc:cc","00:1e:f6:cc:cc:cc","00:1e:f7:cc:cc:cc","00:1f:26:cc:cc:cc","00:1f:27:cc:cc:cc","00:1f:6c:cc:cc:cc","00:1f:6d:cc:cc:cc","00:1f:9d:cc:cc:cc","00:1f:9e:cc:cc:cc","00:1f:c9:cc:cc:cc","00:1f:ca:cc:cc:cc","00:21:1b:cc:cc:cc","00:21:1c:cc:cc:cc","00:21:29:cc:cc:cc","00:21:55:cc:cc:cc","00:21:56:cc:cc:cc","00:21:a0:cc:cc:cc","00:21:a1:cc:cc:cc","00:21:be:cc:cc:cc","00:21:d7:cc:cc:cc","00:21:d8:cc:cc:cc","00:22:0c:cc:cc:cc","00:22:0d:cc:cc:cc","00:22:3a:cc:cc:cc","00:22:55:cc:cc:cc","00:22:56:cc:cc:cc","00:22:6b:cc:cc:cc","00:22:90:cc:cc:cc","00:22:91:cc:cc:cc","00:22:bd:cc:cc:cc","00:22:be:cc:cc:cc","00:22:ce:cc:cc:cc","00:23:04:cc:cc:cc","00:23:05:cc:cc:cc","00:23:33:cc:cc:cc","00:23:34:cc:cc:cc","00:23:5d:cc:cc:cc","00:23:5e:cc:cc:cc","00:23:69:cc:cc:cc","00:23:ab:cc:cc:cc","00:23:ac:cc:cc:cc","00:23:be:cc:cc:cc","00:23:ea:cc:cc:cc","00:23:eb:cc:cc:cc","00:24:13:cc:cc:cc","00:24:14:cc:cc:cc","00:24:50:cc:cc:cc","00:24:51:cc:cc:cc","00:24:97:cc:cc:cc","00:24:98:cc:cc:cc","00:24:c3:cc:cc:cc","00:24:c4:cc:cc:cc","00:24:f7:cc:cc:cc","00:24:f9:cc:cc:cc","00:25:2e:cc:cc:cc","00:25:45:cc:cc:cc","00:25:46:cc:cc:cc","00:25:83:cc:cc:cc","00:25:84:cc:cc:cc","00:25:9c:cc:cc:cc","00:25:b4:cc:cc:cc","00:25:b5:cc:cc:cc","00:26:0a:cc:cc:cc","00:26:0b:cc:cc:cc","00:26:51:cc:cc:cc","00:26:52:cc:cc:cc","00:26:98:cc:cc:cc","00:26:99:cc:cc:cc","00:26:ca:cc:cc:cc","00:26:cb:cc:cc:cc","00:27:0c:cc:cc:cc","00:27:0d:cc:cc:cc","00:27:90:cc:cc:cc","00:27:e3:cc:cc:cc","00:29:c2:cc:cc:cc","00:2a:10:cc:cc:cc","00:2a:6a:cc:cc:cc","00:2c:c8:cc:cc:cc","00:2f:5c:cc:cc:cc","00:30:19:cc:cc:cc","00:30:24:cc:cc:cc","00:30:40:cc:cc:cc","00:30:71:cc:cc:cc","00:30:78:cc:cc:cc","00:30:7b:cc:cc:cc","00:30:80:cc:cc:cc","00:30:85:cc:cc:cc","00:30:94:cc:cc:cc","00:30:96:cc:cc:cc","00:30:a3:cc:cc:cc","00:30:b6:cc:cc:cc","00:30:f2:cc:cc:cc","00:32:17:cc:cc:cc","00:35:1a:cc:cc:cc","00:38:df:cc:cc:cc","00:3a:7d:cc:cc:cc","00:3a:98:cc:cc:cc","00:3a:99:cc:cc:cc","00:3a:9a:cc:cc:cc","00:3a:9b:cc:cc:cc","00:3a:9c:cc:cc:cc","00:3c:10:cc:cc:cc","00:40:0b:cc:cc:cc","00:40:96:cc:cc:cc","00:41:d2:cc:cc:cc","00:42:5a:cc:cc:cc","00:42:68:cc:cc:cc","00:45:1d:cc:cc:cc","00:50:0b:cc:cc:cc","00:50:0f:cc:cc:cc","00:50:14:cc:cc:cc","00:50:2a:cc:cc:cc","00:50:3e:cc:cc:cc","00:50:50:cc:cc:cc","00:50:53:cc:cc:cc","00:50:54:cc:cc:cc","00:50:73:cc:cc:cc","00:50:80:cc:cc:cc","00:50:a2:cc:cc:cc","00:50:a7:cc:cc:cc","00:50:bd:cc:cc:cc","00:50:d1:cc:cc:cc","00:50:e2:cc:cc:cc","00:50:f0:cc:cc:cc","00:56:2b:cc:cc:cc","00:57:d2:cc:cc:cc","00:59:6c:cc:cc:cc","00:59:dc:cc:cc:cc","00:5d:73:cc:cc:cc","00:5f:86:cc:cc:cc","00:60:09:cc:cc:cc","00:60:2f:cc:cc:cc","00:60:3e:cc:cc:cc","00:60:47:cc:cc:cc","00:60:5c:cc:cc:cc","00:60:70:cc:cc:cc","00:60:83:cc:cc:cc","00:62:ec:cc:cc:cc","00:64:40:cc:cc:cc","00:6b:f1:cc:cc:cc","00:6c:bc:cc:cc:cc","00:72:78:cc:cc:cc","00:76:86:cc:cc:cc","00:77:8d:cc:cc:cc","00:78:88:cc:cc:cc","00:7e:95:cc:cc:cc","00:81:c4:cc:cc:cc","00:84:1e:cc:cc:cc","00:87:31:cc:cc:cc","00:87:64:cc:cc:cc","00:8a:96:cc:cc:cc","00:8e:73:cc:cc:cc","00:90:0c:cc:cc:cc","00:90:21:cc:cc:cc","00:90:2b:cc:cc:cc","00:90:5f:cc:cc:cc","00:90:6d:cc:cc:cc","00:90:6f:cc:cc:cc","00:90:86:cc:cc:cc","00:90:92:cc:cc:cc","00:90:a6:cc:cc:cc","00:90:ab:cc:cc:cc","00:90:b1:cc:cc:cc","00:90:bf:cc:cc:cc","00:90:d9:cc:cc:cc","00:90:f2:cc:cc:cc","00:9a:d2:cc:cc:cc","00:9e:1e:cc:cc:cc","00:a2:89:cc:cc:cc","00:a2:ee:cc:cc:cc","00:a3:8e:cc:cc:cc","00:a3:d1:cc:cc:cc","00:a5:bf:cc:cc:cc","00:a6:ca:cc:cc:cc","00:a7:42:cc:cc:cc","00:aa:6e:cc:cc:cc","00:af:1f:cc:cc:cc","00:b0:4a:cc:cc:cc","00:b0:64:cc:cc:cc","00:b0:8e:cc:cc:cc","00:b0:c2:cc:cc:cc","00:b0:e1:cc:cc:cc","00:b1:e3:cc:cc:cc","00:b6:70:cc:cc:cc","00:b7:71:cc:cc:cc","00:b8:b3:cc:cc:cc","00:bc:60:cc:cc:cc","00:be:75:cc:cc:cc","00:bf:77:cc:cc:cc","00:c1:64:cc:cc:cc","00:c1:b1:cc:cc:cc","00:c8:8b:cc:cc:cc","00:ca:e5:cc:cc:cc","00:cc:fc:cc:cc:cc","00:d0:06:cc:cc:cc","00:d0:58:cc:cc:cc","00:d0:63:cc:cc:cc","00:d0:79:cc:cc:cc","00:d0:90:cc:cc:cc","00:d0:97:cc:cc:cc","00:d0:ba:cc:cc:cc","00:d0:bb:cc:cc:cc","00:d0:bc:cc:cc:cc","00:d0:c0:cc:cc:cc","00:d0:d3:cc:cc:cc","00:d0:e4:cc:cc:cc","00:d0:ff:cc:cc:cc","00:d6:fe:cc:cc:cc","00:d7:8f:cc:cc:cc","00:da:55:cc:cc:cc","00:de:fb:cc:cc:cc","00:df:1d:cc:cc:cc","00:e0:14:cc:cc:cc","00:e0:1e:cc:cc:cc","00:e0:34:cc:cc:cc",
"00:e0:4f:cc:cc:cc","00:e0:8f:cc:cc:cc","00:e0:a3:cc:cc:cc","00:e0:b0:cc:cc:cc","00:e0:f7:cc:cc:cc","00:e0:f9:cc:cc:cc","00:e0:fe:cc:cc:cc","00:e1:6d:cc:cc:cc","00:ea:bd:cc:cc:cc","00:eb:d5:cc:cc:cc","00:ee:ab:cc:cc:cc","00:f2:8b:cc:cc:cc","00:f6:63:cc:cc:cc","00:f8:2c:cc:cc:cc","00:fc:ba:cc:cc:cc","00:fd:22:cc:cc:cc","00:fe:c8:cc:cc:cc","04:2a:e2:cc:cc:cc","04:5f:b9:cc:cc:cc","04:62:73:cc:cc:cc","04:6c:9d:cc:cc:cc","04:76:b0:cc:cc:cc","04:a7:41:cc:cc:cc","04:bd:97:cc:cc:cc","04:c5:a4:cc:cc:cc","04:da:d2:cc:cc:cc","04:e3:87:cc:cc:cc","04:eb:40:cc:cc:cc","04:fe:7f:cc:cc:cc","08:0f:e5:cc:cc:cc","08:17:35:cc:cc:cc","08:1f:f3:cc:cc:cc","08:45:d1:cc:cc:cc","08:4f:a9:cc:cc:cc","08:4f:f9:cc:cc:cc","08:7b:87:cc:cc:cc","08:80:39:cc:cc:cc","08:96:ad:cc:cc:cc","08:97:07:cc:cc:cc","08:cc:68:cc:cc:cc","08:cc:a7:cc:cc:cc","08:d0:9f:cc:cc:cc","08:ec:f5:cc:cc:cc","08:f1:b3:cc:cc:cc","08:f3:fb:cc:cc:cc","08:f4:f0:cc:cc:cc","0c:11:67:cc:cc:cc","0c:27:24:cc:cc:cc","0c:68:03:cc:cc:cc","0c:75:bd:cc:cc:cc","0c:7b:c8:cc:cc:cc","0c:85:25:cc:cc:cc","0c:8d:db:cc:cc:cc","0c:af:31:cc:cc:cc","0c:d0:f8:cc:cc:cc","0c:d5:d3:cc:cc:cc","0c:d9:96:cc:cc:cc","0c:f5:a4:cc:cc:cc","10:05:ca:cc:cc:cc","10:06:ed:cc:cc:cc","10:57:25:cc:cc:cc","10:5f:49:cc:cc:cc","10:8c:cf:cc:cc:cc","10:96:c6:cc:cc:cc","10:a8:29:cc:cc:cc","10:b3:c6:cc:cc:cc","10:b3:d5:cc:cc:cc","10:b3:d6:cc:cc:cc","10:bd:18:cc:cc:cc","10:e3:76:cc:cc:cc","10:ea:59:cc:cc:cc","10:f3:11:cc:cc:cc","10:f9:20:cc:cc:cc","14:16:9d:cc:cc:cc","14:84:73:cc:cc:cc","14:9f:43:cc:cc:cc","14:a2:a0:cc:cc:cc","14:bc:68:cc:cc:cc","18:33:9d:cc:cc:cc","18:55:0f:cc:cc:cc","18:59:33:cc:cc:cc","18:59:f5:cc:cc:cc","18:80:90:cc:cc:cc","18:8b:45:cc:cc:cc","18:8b:9d:cc:cc:cc","18:9c:5d:cc:cc:cc","18:e7:28:cc:cc:cc","18:ef:63:cc:cc:cc","18:f9:35:cc:cc:cc","1c:17:d3:cc:cc:cc","1c:1d:86:cc:cc:cc","1c:6a:7a:cc:cc:cc","1c:aa:07:cc:cc:cc","1c:d1:e0:cc:cc:cc","1c:de:a7:cc:cc:cc","1c:df:0f:cc:cc:cc","1c:e6:c7:cc:cc:cc","1c:e8:5d:cc:cc:cc","1c:fc:17:cc:cc:cc","20:0b:c5:cc:cc:cc","20:37:06:cc:cc:cc","20:3a:07:cc:cc:cc","20:4c:9e:cc:cc:cc","20:aa:4b:cc:cc:cc","20:bb:c0:cc:cc:cc","20:cc:27:cc:cc:cc","20:cf:ae:cc:cc:cc","20:db:ea:cc:cc:cc","20:f1:20:cc:cc:cc","24:01:c7:cc:cc:cc","24:16:1b:cc:cc:cc","24:16:9d:cc:cc:cc","24:2a:04:cc:cc:cc","24:36:da:cc:cc:cc","24:37:4c:cc:cc:cc","24:6c:84:cc:cc:cc","24:76:7d:cc:cc:cc","24:7e:12:cc:cc:cc","24:81:3b:cc:cc:cc","24:b6:57:cc:cc:cc","24:d5:e4:cc:cc:cc","24:d7:9c:cc:cc:cc","24:e9:b3:cc:cc:cc","28:34:a2:cc:cc:cc","28:52:61:cc:cc:cc","28:6b:5c:cc:cc:cc","28:6f:7f:cc:cc:cc","28:93:fe:cc:cc:cc","28:94:0f:cc:cc:cc","28:ac:9e:cc:cc:cc","28:af:fd:cc:cc:cc","28:b5:91:cc:cc:cc","28:c7:ce:cc:cc:cc","2c:01:b5:cc:cc:cc","2c:0b:e9:cc:cc:cc","2c:1a:05:cc:cc:cc","2c:31:24:cc:cc:cc","2c:33:11:cc:cc:cc","2c:36:f8:cc:cc:cc","2c:3e:cf:cc:cc:cc","2c:3f:0b:cc:cc:cc","2c:3f:38:cc:cc:cc","2c:4f:52:cc:cc:cc","2c:54:2d:cc:cc:cc","2c:57:41:cc:cc:cc","2c:5a:0f:cc:cc:cc","2c:73:a0:cc:cc:cc","2c:86:d2:cc:cc:cc","2c:ab:a4:cc:cc:cc","2c:ab:eb:cc:cc:cc","2c:d0:2d:cc:cc:cc","2c:e3:8e:cc:cc:cc","2c:f8:14:cc:cc:cc","2c:f8:9b:cc:cc:cc","30:01:af:cc:cc:cc","30:37:a6:cc:cc:cc","30:3b:49:cc:cc:cc","30:8b:b2:cc:cc:cc","30:e4:db:cc:cc:cc","30:f7:0d:cc:cc:cc","30:fe:fa:cc:cc:cc","34:1b:2d:cc:cc:cc","34:56:fe:cc:cc:cc","34:58:8a:cc:cc:cc","34:5d:a8:cc:cc:cc","34:62:88:cc:cc:cc","34:6f:90:cc:cc:cc","34:70:69:cc:cc:cc","34:73:2d:cc:cc:cc","34:88:18:cc:cc:cc","34:a8:4e:cc:cc:cc","34:b8:83:cc:cc:cc","34:bd:c8:cc:cc:cc","34:bd:fa:cc:cc:cc","34:db:fd:cc:cc:cc","34:ed:1b:cc:cc:cc","34:f8:e7:cc:cc:cc","38:0e:4d:cc:cc:cc","38:1c:1a:cc:cc:cc","38:20:56:cc:cc:cc","38:5f:66:cc:cc:cc","38:84:79:cc:cc:cc","38:90:a5:cc:cc:cc","38:91:b7:cc:cc:cc","38:aa:09:cc:cc:cc","38:c8:5c:cc:cc:cc","38:ed:18:cc:cc:cc","38:fd:f8:cc:cc:cc","3c:08:f6:cc:cc:cc","3c:0e:23:cc:cc:cc","3c:13:cc:cc:cc:cc","3c:26:e4:cc:cc:cc","3c:41:0e:cc:cc:cc","3c:51:0e:cc:cc:cc","3c:57:31:cc:cc:cc","3c:5e:c3:cc:cc:cc","3c:8b:7f:cc:cc:cc","3c:ce:73:cc:cc:cc","3c:df:1e:cc:cc:cc","3c:fe:ac:cc:cc:cc","40:01:7a:cc:cc:cc","40:06:d5:cc:cc:cc","40:14:82:cc:cc:cc","40:27:a8:cc:cc:cc","40:42:44:cc:cc:cc","40:55:39:cc:cc:cc","40:a6:e8:cc:cc:cc","40:b5:c1:cc:cc:cc","40:ce:24:cc:cc:cc","40:f0:78:cc:cc:cc","40:f4:9f:cc:cc:cc","40:f4:ec:cc:cc:cc","44:03:a7:cc:cc:cc","44:2b:03:cc:cc:cc","44:58:29:cc:cc:cc","44:64:3c:cc:cc:cc","44:88:16:cc:cc:cc","44:8d:d5:cc:cc:cc","44:ad:d9:cc:cc:cc","44:ae:25:cc:cc:cc","44:b6:be:cc:cc:cc","44:c2:0c:cc:cc:cc","44:d3:ca:cc:cc:cc","44:e0:8e:cc:cc:cc","44:e4:d9:cc:cc:cc","48:00:b3:cc:cc:cc","48:1b:a4:cc:cc:cc","48:1d:70:cc:cc:cc","48:2e:72:cc:cc:cc","48:44:87:cc:cc:cc","48:74:10:cc:cc:cc","48:80:02:cc:cc:cc","48:8b:0a:cc:cc:cc","48:91:d5:cc:cc:cc","48:a1:70:cc:cc:cc","48:f8:b3:cc:cc:cc","4c:00:82:cc:cc:cc","4c:01:f7:cc:cc:cc","4c:42:1e:cc:cc:cc","4c:4e:35:cc:cc:cc","4c:5d:3c:cc:cc:cc","4c:71:0c:cc:cc:cc","4c:71:0d:cc:cc:cc","4c:77:6d:cc:cc:cc","4c:83:de:cc:cc:cc","4c:a6:4d:cc:cc:cc","4c:bc:48:cc:cc:cc","4c:c8:a1:cc:cc:cc","4c:d0:f9:cc:cc:cc","4c:e1:75:cc:cc:cc","4c:e1:76:cc:cc:cc","4c:ec:0f:cc:cc:cc","50:00:e0:cc:cc:cc","50:06:04:cc:cc:cc","50:06:ab:cc:cc:cc","50:0f:80:cc:cc:cc","50:17:ff:cc:cc:cc","50:1c:b0:cc:cc:cc","50:1c:bf:cc:cc:cc","50:2f:a8:cc:cc:cc","50:39:55:cc:cc:cc","50:3d:e5:cc:cc:cc","50:49:21:cc:cc:cc","50:57:a8:cc:cc:cc","50:5c:88:cc:cc:cc","50:61:bf:cc:cc:cc","50:67:ae:cc:cc:cc","50:87:89:cc:cc:cc","50:f7:22:cc:cc:cc","54:4a:00:cc:cc:cc","54:51:de:cc:cc:cc","54:75:d0:cc:cc:cc","54:78:1a:cc:cc:cc","54:7c:69:cc:cc:cc","54:7f:ee:cc:cc:cc","54:86:bc:cc:cc:cc","54:88:de:cc:cc:cc","54:8a:ba:cc:cc:cc","54:9f:c6:cc:cc:cc","54:a2:74:cc:cc:cc","54:d4:6f:cc:cc:cc","58:0a:20:cc:cc:cc","58:35:d9:cc:cc:cc","58:56:9f:cc:cc:cc","58:6d:8f:cc:cc:cc","58:8b:1c:cc:cc:cc","58:8d:09:cc:cc:cc","58:97:1e:cc:cc:cc","58:97:bd:cc:cc:cc","58:ac:78:cc:cc:cc","58:bc:27:cc:cc:cc","58:bf:ea:cc:cc:cc","58:df:59:cc:cc:cc","58:f3:9c:cc:cc:cc","5c:06:10:cc:cc:cc","5c:31:92:cc:cc:cc","5c:3e:06:cc:cc:cc","5c:50:15:cc:cc:cc","5c:5a:c7:cc:cc:cc","5c:64:f1:cc:cc:cc","5c:71:0d:cc:cc:cc","5c:83:8f:cc:cc:cc","5c:a4:8a:cc:cc:cc","5c:a6:2d:cc:cc:cc","5c:b1:2e:cc:cc:cc","5c:e1:76:cc:cc:cc","5c:fc:66:cc:cc:cc","60:26:aa:cc:cc:cc","60:2a:d0:cc:cc:cc","60:73:5c:cc:cc:cc","60:b9:c0:cc:cc:cc","64:00:f1:cc:cc:cc","64:08:64:cc:cc:cc","64:12:25:cc:cc:cc","64:16:8d:cc:cc:cc","64:3a:ea:cc:cc:cc","64:8f:3e:cc:cc:cc","64:9e:f3:cc:cc:cc","64:a0:e7:cc:cc:cc","64:ae:0c:cc:cc:cc","64:d8:14:cc:cc:cc","64:d9:89:cc:cc:cc","64:e9:50:cc:cc:cc","64:f6:9d:cc:cc:cc","68:04:89:cc:cc:cc","68:2c:7b:cc:cc:cc","68:3a:1e:cc:cc:cc","68:3b:78:cc:cc:cc","68:49:92:cc:cc:cc","68:71:61:cc:cc:cc","68:79:09:cc:cc:cc","68:7d:b4:cc:cc:cc","68:7f:74:cc:cc:cc","68:86:a7:cc:cc:cc","68:87:c6:cc:cc:cc","68:99:cd:cc:cc:cc","68:9c:e2:cc:cc:cc","68:9e:0b:cc:cc:cc","68:bc:0c:cc:cc:cc","68:bd:ab:cc:cc:cc","68:ca:e4:cc:cc:cc","68:d9:72:cc:cc:cc","68:e5:9e:cc:cc:cc","68:ee:96:cc:cc:cc","68:ef:bd:cc:cc:cc","6c:03:09:cc:cc:cc","6c:03:b5:cc:cc:cc","6c:13:d5:cc:cc:cc","6c:20:56:cc:cc:cc","6c:29:d2:cc:cc:cc","6c:31:0e:cc:cc:cc","6c:41:0e:cc:cc:cc","6c:41:6a:cc:cc:cc","6c:4e:f6:cc:cc:cc","6c:4f:a1:cc:cc:cc","6c:50:4d:cc:cc:cc","6c:5e:3b:cc:cc:cc","6c:6c:d3:cc:cc:cc","6c:71:0d:cc:cc:cc","6c:7d:b7:cc:cc:cc","6c:7f:0c:cc:cc:cc","6c:8b:d3:cc:cc:cc","6c:8d:77:cc:cc:cc","6c:99:89:cc:cc:cc","6c:9c:ed:cc:cc:cc","6c:ab:05:cc:cc:cc","6c:b2:ae:cc:cc:cc","6c:c3:b2:cc:cc:cc","6c:d6:e3:cc:cc:cc","6c:dd:30:cc:cc:cc","6c:de:a9:cc:cc:cc","6c:ef:bd:cc:cc:cc","6c:fa:89:cc:cc:cc","70:01:b5:cc:cc:cc","70:0b:4f:cc:cc:cc","70:0f:6a:cc:cc:cc","70:10:5c:cc:cc:cc","70:18:a7:cc:cc:cc","70:1f:53:cc:cc:cc","70:35:09:cc:cc:cc","70:61:7b:cc:cc:cc","70:69:5a:cc:cc:cc","70:6b:b9:cc:cc:cc","70:6d:15:cc:cc:cc","70:6e:6d:cc:cc:cc","70:70:8b:cc:cc:cc","70:79:b3:cc:cc:cc","70:7d:b9:cc:cc:cc","70:81:05:cc:cc:cc","70:a9:83:cc:cc:cc","70:b3:17:cc:cc:cc","70:bc:48:cc:cc:cc","70:bd:96:cc:cc:cc","70:c9:c6:cc:cc:cc","70:ca:9b:cc:cc:cc","70:d3:79:cc:cc:cc","70:da:48:cc:cc:cc","70:db:98:cc:cc:cc","70:df:2f:cc:cc:cc","70:e4:22:cc:cc:cc","70:ea:1a:cc:cc:cc","70:f0:96:cc:cc:cc","70:f3:5a:cc:cc:cc","74:11:b2:cc:cc:cc","74:26:ac:cc:cc:cc","74:54:7d:cc:cc:cc","74:86:0b:cc:cc:cc","74:88:bb:cc:cc:cc","74:8f:c2:cc:cc:cc","74:a0:2f:cc:cc:cc","74:a2:e6:cc:cc:cc","74:ad:98:cc:cc:cc","74:e2:e7:cc:cc:cc","78:02:b1:cc:cc:cc","78:0c:f0:cc:cc:cc","78:0f:81:cc:cc:cc","78:24:be:cc:cc:cc","78:64:a0:cc:cc:cc","78:72:5d:cc:cc:cc","78:85:17:cc:cc:cc","78:ba:f9:cc:cc:cc","78:bc:1a:cc:cc:cc","78:da:6e:cc:cc:cc","78:f1:c6:cc:cc:cc","7c:0e:ce:cc:cc:cc","7c:21:0d:cc:cc:cc","7c:21:0e:cc:cc:cc","7c:31:0e:cc:cc:cc","7c:69:f6:cc:cc:cc","7c:95:f3:cc:cc:cc","7c:ad:4f:cc:cc:cc","7c:ad:74:cc:cc:cc","7c:b2:1b:cc:cc:cc","7c:b3:53:cc:cc:cc","7c:f8:80:cc:cc:cc","80:24:8f:cc:cc:cc","80:27:6c:cc:cc:cc","80:2d:bf:cc:cc:cc","80:6a:00:cc:cc:cc","80:e0:1d:cc:cc:cc","80:e8:6f:cc:cc:cc","84:0c:6d:cc:cc:cc","84:3d:c6:cc:cc:cc","84:5a:3e:cc:cc:cc","84:78:ac:cc:cc:cc","84:80:2d:cc:cc:cc","84:8a:8d:cc:cc:cc","84:8d:c7:cc:cc:cc","84:b2:61:cc:cc:cc","84:b5:17:cc:cc:cc","84:b8:02:cc:cc:cc","84:eb:ef:cc:cc:cc","84:f1:47:cc:cc:cc","84:ff:c2:cc:cc:cc","88:1d:fc:cc:cc:cc","88:43:e1:cc:cc:cc","88:4f:59:cc:cc:cc","88:5a:92:cc:cc:cc","88:75:56:cc:cc:cc","88:7a:bc:cc:cc:cc","88:90:8d:cc:cc:cc","88:9c:ad:cc:cc:cc","88:f0:31:cc:cc:cc","88:f0:77:cc:cc:cc","88:fc:5d:cc:cc:cc","8c:1e:80:cc:cc:cc","8c:44:a5:cc:cc:cc","8c:60:4f:cc:cc:cc","8c:84:42:cc:cc:cc","8c:88:81:cc:cc:cc","8c:94:1f:cc:cc:cc","8c:94:61:cc:cc:cc","8c:b5:0e:cc:cc:cc","8c:b6:4f:cc:cc:cc","90:56:71:cc:cc:cc","90:77:ee:cc:cc:cc","90:88:55:cc:cc:cc","90:e9:5e:cc:cc:cc","90:eb:50:cc:cc:cc","94:0d:4b:cc:cc:cc","94:33:d8:cc:cc:cc","94:ae:f0:cc:cc:cc","94:d4:69:cc:cc:cc","98:18:88:cc:cc:cc","98:a2:c0:cc:cc:cc","98:d7:e1:cc:cc:cc","98:fc:11:cc:cc:cc","9c:09:8b:cc:cc:cc","9c:38:18:cc:cc:cc","9c:4e:20:cc:cc:cc","9c:54:16:cc:cc:cc","9c:57:ad:cc:cc:cc","9c:66:97:cc:cc:cc","9c:a9:b8:cc:cc:cc","9c:af:ca:cc:cc:cc","9c:d5:7d:cc:cc:cc","9c:e1:76:cc:cc:cc","9c:e3:30:cc:cc:cc","a0:0f:37:cc:cc:cc","a0:23:9f:cc:cc:cc",
"a0:33:4f:cc:cc:cc","a0:3d:6e:cc:cc:cc","a0:3d:6f:cc:cc:cc","a0:55:4f:cc:cc:cc","a0:93:51:cc:cc:cc","a0:a4:7f:cc:cc:cc","a0:b4:39:cc:cc:cc","a0:bc:6f:cc:cc:cc","a0:c7:d2:cc:cc:cc","a0:cf:5b:cc:cc:cc","a0:e0:af:cc:cc:cc","a0:ec:f9:cc:cc:cc","a0:f8:49:cc:cc:cc","a4:00:4e:cc:cc:cc","a4:0c:c3:cc:cc:cc","a4:10:b6:cc:cc:cc","a4:11:bb:cc:cc:cc","a4:18:75:cc:cc:cc","a4:4c:11:cc:cc:cc","a4:53:0e:cc:cc:cc","a4:56:30:cc:cc:cc","a4:6c:2a:cc:cc:cc","a4:78:06:cc:cc:cc","a4:88:73:cc:cc:cc","a4:93:4c:cc:cc:cc","a4:97:00:cc:cc:cc","a4:9b:cd:cc:cc:cc","a4:a2:4a:cc:cc:cc","a4:a5:84:cc:cc:cc","a4:b2:39:cc:cc:cc","a4:b4:39:cc:cc:cc","a4:dc:d5:cc:cc:cc","a8:0c:0d:cc:cc:cc","a8:46:9d:cc:cc:cc","a8:4f:b1:cc:cc:cc","a8:9d:21:cc:cc:cc","a8:b1:d4:cc:cc:cc","a8:b4:56:cc:cc:cc","ac:17:c8:cc:cc:cc","ac:2a:a1:cc:cc:cc","ac:3a:67:cc:cc:cc","ac:4a:56:cc:cc:cc","ac:4a:67:cc:cc:cc","ac:69:cf:cc:cc:cc","ac:7a:56:cc:cc:cc","ac:7e:8a:cc:cc:cc","ac:a0:16:cc:cc:cc","ac:bc:d9:cc:cc:cc","ac:bd:f7:cc:cc:cc","ac:c3:e5:cc:cc:cc","ac:d3:1d:cc:cc:cc","ac:f2:c5:cc:cc:cc","ac:f5:e6:cc:cc:cc","b0:00:b4:cc:cc:cc","b0:26:80:cc:cc:cc","b0:7d:47:cc:cc:cc","b0:8b:cf:cc:cc:cc","b0:8b:d0:cc:cc:cc","b0:8d:57:cc:cc:cc","b0:90:7e:cc:cc:cc","b0:a6:51:cc:cc:cc","b0:aa:77:cc:cc:cc","b0:c5:3c:cc:cc:cc","b0:fa:eb:cc:cc:cc","b4:02:16:cc:cc:cc","b4:14:89:cc:cc:cc","b4:4c:90:cc:cc:cc","b4:a4:e3:cc:cc:cc","b4:a8:b9:cc:cc:cc","b4:ca:dd:cc:cc:cc","b4:de:31:cc:cc:cc","b4:df:91:cc:cc:cc","b4:e9:b0:cc:cc:cc","b8:07:56:cc:cc:cc","b8:11:4b:cc:cc:cc","b8:38:61:cc:cc:cc","b8:62:1f:cc:cc:cc","b8:a3:77:cc:cc:cc","b8:ab:61:cc:cc:cc","b8:b4:c9:cc:cc:cc","b8:be:bf:cc:cc:cc","bc:16:65:cc:cc:cc","bc:16:f5:cc:cc:cc","bc:26:c7:cc:cc:cc","bc:2c:e6:cc:cc:cc","bc:33:40:cc:cc:cc","bc:4a:56:cc:cc:cc","bc:5a:56:cc:cc:cc","bc:67:1c:cc:cc:cc","bc:8d:1f:cc:cc:cc","bc:b1:d3:cc:cc:cc","bc:c4:93:cc:cc:cc","bc:c8:10:cc:cc:cc","bc:d1:65:cc:cc:cc","bc:d2:95:cc:cc:cc","bc:db:09:cc:cc:cc","bc:e7:12:cc:cc:cc","bc:f1:f2:cc:cc:cc","bc:fa:eb:cc:cc:cc","c0:14:fe:cc:cc:cc","c0:25:5c:cc:cc:cc","c0:2c:17:cc:cc:cc","c0:62:6b:cc:cc:cc","c0:64:e4:cc:cc:cc","c0:67:af:cc:cc:cc","c0:7b:bc:cc:cc:cc","c0:8b:2a:cc:cc:cc","c0:8c:60:cc:cc:cc","c0:c1:c0:cc:cc:cc","c0:c6:87:cc:cc:cc","c0:f8:7f:cc:cc:cc","c4:0a:cb:cc:cc:cc","c4:14:3c:cc:cc:cc","c4:14:a2:cc:cc:cc","c4:18:fc:cc:cc:cc","c4:44:a0:cc:cc:cc","c4:46:06:cc:cc:cc","c4:4d:84:cc:cc:cc","c4:64:13:cc:cc:cc","c4:71:fe:cc:cc:cc","c4:72:95:cc:cc:cc","c4:7d:4f:cc:cc:cc","c4:7e:e0:cc:cc:cc","c4:8b:a3:cc:cc:cc","c4:ab:4d:cc:cc:cc","c4:b2:39:cc:cc:cc","c4:b3:6a:cc:cc:cc","c4:b9:cd:cc:cc:cc","c4:c6:03:cc:cc:cc","c4:d6:66:cc:cc:cc","c4:f7:d5:cc:cc:cc","c8:00:84:cc:cc:cc","c8:28:e5:cc:cc:cc","c8:47:09:cc:cc:cc","c8:4c:75:cc:cc:cc","c8:60:8f:cc:cc:cc","c8:82:34:cc:cc:cc","c8:84:a1:cc:cc:cc","c8:9c:1d:cc:cc:cc","c8:b3:73:cc:cc:cc","c8:d7:19:cc:cc:cc","c8:f9:f9:cc:cc:cc","c8:fb:26:cc:cc:cc","cc:03:d9:cc:cc:cc","cc:0d:ec:cc:cc:cc","cc:16:7e:cc:cc:cc","cc:36:cf:cc:cc:cc","cc:46:d6:cc:cc:cc","cc:5a:53:cc:cc:cc","cc:6a:33:cc:cc:cc","cc:6e:2a:cc:cc:cc","cc:70:ed:cc:cc:cc","cc:79:d7:cc:cc:cc","cc:7f:75:cc:cc:cc","cc:7f:76:cc:cc:cc","cc:8e:71:cc:cc:cc","cc:90:70:cc:cc:cc","cc:98:91:cc:cc:cc","cc:9c:3e:cc:cc:cc","cc:b6:c8:cc:cc:cc","cc:d3:42:cc:cc:cc","cc:d5:39:cc:cc:cc","cc:d8:c1:cc:cc:cc","cc:db:93:cc:cc:cc","cc:ed:4d:cc:cc:cc","cc:ef:48:cc:cc:cc","d0:09:c8:cc:cc:cc","d0:57:4c:cc:cc:cc","d0:72:dc:cc:cc:cc","d0:85:43:cc:cc:cc","d0:a5:a6:cc:cc:cc","d0:c2:82:cc:cc:cc","d0:c7:89:cc:cc:cc","d0:d0:fd:cc:cc:cc","d0:dc:2c:cc:cc:cc","d0:e0:42:cc:cc:cc","d0:ec:35:cc:cc:cc","d4:2c:44:cc:cc:cc","d4:66:24:cc:cc:cc","d4:6a:35:cc:cc:cc","d4:6d:50:cc:cc:cc","d4:77:98:cc:cc:cc","d4:78:9b:cc:cc:cc","d4:7f:35:cc:cc:cc","d4:8c:b5:cc:cc:cc","d4:a0:2a:cc:cc:cc","d4:ad:71:cc:cc:cc","d4:ad:bd:cc:cc:cc","d4:c9:3c:cc:cc:cc","d4:d7:48:cc:cc:cc","d4:e8:80:cc:cc:cc","d4:eb:68:cc:cc:cc","d8:24:bd:cc:cc:cc","d8:53:ad:cc:cc:cc","d8:67:d9:cc:cc:cc","d8:b1:90:cc:cc:cc","dc:05:39:cc:cc:cc","dc:0b:09:cc:cc:cc","dc:77:4c:cc:cc:cc","dc:7b:94:cc:cc:cc","dc:8c:37:cc:cc:cc","dc:a5:f4:cc:cc:cc","dc:ce:c1:cc:cc:cc","dc:eb:94:cc:cc:cc","dc:f7:19:cc:cc:cc","e0:0e:da:cc:cc:cc","e0:2a:66:cc:cc:cc","e0:2f:6d:cc:cc:cc","e0:55:3d:cc:cc:cc","e0:5f:b9:cc:cc:cc","e0:69:ba:cc:cc:cc","e0:89:9d:cc:cc:cc","e0:8c:3c:cc:cc:cc","e0:ac:f1:cc:cc:cc","e0:cb:bc:cc:cc:cc","e0:d1:73:cc:cc:cc","e0:d3:b4:cc:cc:cc","e0:d4:91:cc:cc:cc","e4:1f:7b:cc:cc:cc","e4:37:9f:cc:cc:cc","e4:38:7e:cc:cc:cc","e4:48:c7:cc:cc:cc","e4:4e:2d:cc:cc:cc","e4:55:a8:cc:cc:cc","e4:62:c4:cc:cc:cc","e4:89:ca:cc:cc:cc","e4:a4:1c:cc:cc:cc","e4:aa:5d:cc:cc:cc","e4:c7:22:cc:cc:cc","e4:d3:f1:cc:cc:cc","e8:04:62:cc:cc:cc","e8:0a:b9:cc:cc:cc","e8:40:40:cc:cc:cc","e8:5c:0a:cc:cc:cc","e8:65:49:cc:cc:cc","e8:79:a3:cc:cc:cc","e8:b7:48:cc:cc:cc","e8:ba:70:cc:cc:cc","e8:bc:e4:cc:cc:cc","e8:d3:22:cc:cc:cc","e8:dc:6c:cc:cc:cc","e8:eb:34:cc:cc:cc","e8:ed:f3:cc:cc:cc","ec:01:d5:cc:cc:cc","ec:19:2e:cc:cc:cc","ec:1d:8b:cc:cc:cc","ec:30:91:cc:cc:cc","ec:44:76:cc:cc:cc","ec:bb:78:cc:cc:cc","ec:bd:1d:cc:cc:cc","ec:c0:18:cc:cc:cc","ec:c8:82:cc:cc:cc","ec:ce:13:cc:cc:cc","ec:dd:24:cc:cc:cc","ec:e1:a9:cc:cc:cc","ec:f4:0c:cc:cc:cc","f0:03:bc:cc:cc:cc","f0:1d:2d:cc:cc:cc","f0:25:72:cc:cc:cc","f0:29:29:cc:cc:cc","f0:4a:02:cc:cc:cc","f0:78:16:cc:cc:cc","f0:7f:06:cc:cc:cc","f0:9e:63:cc:cc:cc","f0:b2:e5:cc:cc:cc","f0:d8:05:cc:cc:cc","f0:f7:55:cc:cc:cc","f4:0f:1b:cc:cc:cc","f4:1f:c2:cc:cc:cc","f4:33:92:cc:cc:cc","f4:4b:2a:cc:cc:cc","f4:4e:05:cc:cc:cc","f4:5f:d4:cc:cc:cc","f4:74:70:cc:cc:cc","f4:7f:35:cc:cc:cc","f4:ac:c1:cc:cc:cc","f4:bd:9e:cc:cc:cc","f4:cf:e2:cc:cc:cc","f4:db:e6:cc:cc:cc","f4:ea:67:cc:cc:cc","f4:ee:31:cc:cc:cc","f8:0b:cb:cc:cc:cc","f8:0f:6f:cc:cc:cc","f8:14:dd:cc:cc:cc","f8:39:18:cc:cc:cc","f8:4f:57:cc:cc:cc","f8:66:f2:cc:cc:cc","f8:68:ff:cc:cc:cc","f8:6b:d9:cc:cc:cc","f8:72:ea:cc:cc:cc","f8:7a:41:cc:cc:cc","f8:7b:20:cc:cc:cc","f8:9e:28:cc:cc:cc","f8:a5:c5:cc:cc:cc","f8:a7:3a:cc:cc:cc","f8:b7:e2:cc:cc:cc","f8:c2:88:cc:cc:cc","f8:c6:50:cc:cc:cc","f8:e5:7e:cc:cc:cc","f8:e9:4f:cc:cc:cc","fc:58:9a:cc:cc:cc","fc:5b:39:cc:cc:cc","fc:94:2e:cc:cc:cc","fc:99:47:cc:cc:cc","fc:fb:fb:cc:cc:cc"]

class FlowManager:
    """
    Manages network flows, handles flow detection, timeouts, and statistics.
    """
    
    def __init__(self, flow_timeout: float = 1200.0, max_flows: int = 100000):
        """
        Initialize flow manager.
        
        Args:
            flow_timeout: Flow timeout in seconds (default 20 minutes)
            max_flows: Maximum number of concurrent flows
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        
        # Active flows storage
        self.active_flows: Dict[str, Flow] = {}
        self.completed_flows: List[Flow] = []
        
        # Statistics
        self.total_packets_processed = 0
        self.protocol_stats = defaultdict(int)
        self.flow_stats = defaultdict(int)
        
        self.logger = logging.getLogger(__name__)
    
    def process_packet(self, scapy_packet, frame_number: int) -> Optional[Flow]:
        """
        Process a single packet and assign it to appropriate flow.
        
        Args:
            scapy_packet: Scapy packet object
            frame_number: Sequential frame number
            
        Returns:
            Flow object if packet was assigned to a flow, None otherwise
        """
        try:
            # Create appropriate packet object based on protocol
            packet = self._create_packet_object(scapy_packet, frame_number)
            
            self.total_packets_processed += 1
            protocol = packet.get_protocol_type()
            self.protocol_stats[protocol] += 1
            
            # Get flow key for this packet
            flow_key = packet.get_flow_key()
            
            # Check if flow already exists
            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                flow.add_packet(packet)
                
                # Check if TCP flow should be closed
                if isinstance(packet, TCPPacket) and packet.is_connection_end():
                    self._close_flow(flow_key)
                    
            else:
                # Create new flow
                if len(self.active_flows) >= self.max_flows:
                    self._cleanup_old_flows()
                
                flow = Flow(flow_key, packet)
                self.active_flows[flow_key] = flow
                self.flow_stats['created'] += 1
            
            # Periodic cleanup of timed-out flows
            if self.total_packets_processed % 10000 == 0:
                self._cleanup_timed_out_flows()
            
            return self.active_flows.get(flow_key)
            
        except Exception as e:
            self.logger.error(f"Error processing packet {frame_number}: {e}")
            return None
    
    def _create_packet_object(self, scapy_packet, frame_number: int) -> BasePacket:
        """Create appropriate packet object based on protocol."""
        try:
            # Check for TCP
            if scapy_packet.haslayer('TCP'):
                return TCPPacket(scapy_packet, frame_number)
            
            # Check for UDP (and its sub-protocols)
            elif scapy_packet.haslayer('UDP'):
                return UDPPacket(scapy_packet, frame_number)
            
            # Check for Layer 2 protocols
            elif scapy_packet.haslayer('STP'):
                return STPPacket(scapy_packet, frame_number)
            
            elif scapy_packet.haslayer('ARP'):
                return ARPPacket(scapy_packet, frame_number)
            
            # Check for LLC frames
            elif scapy_packet.haslayer('LLC'):
                # Check for specific LLC-based protocols
                if self._is_cdp_packet(scapy_packet):
                    self.logger.debug(f"CDP packet detected at frame {frame_number}")
                    return CDPPacket(scapy_packet, frame_number)
                elif self._is_lldp_packet(scapy_packet):
                    self.logger.debug(f"LLDP packet detected at frame {frame_number}")
                    return LLDPPacket(scapy_packet, frame_number)
                elif self._is_dtp_packet(scapy_packet):
                    self.logger.debug(f"DTP packet detected at frame {frame_number}")
                    return DTPPacket(scapy_packet, frame_number)
                elif self._is_vtp_packet(scapy_packet):
                    self.logger.debug(f"VTP packet detected at frame {frame_number}")
                    return VTPPacket(scapy_packet, frame_number)
                elif self._is_isl_packet(scapy_packet):
                    self.logger.debug(f"ISL packet detected at frame {frame_number}")
                    return ISLPacket(scapy_packet, frame_number)
                else:
                    return LLCPacket(scapy_packet, frame_number)
            
            # Check for LLDP by MAC address and payload (more specific detection)
            elif self._is_lldp_packet(scapy_packet):
                self.logger.debug(f"LLDP packet detected by enhanced analysis at frame {frame_number}")
                return LLDPPacket(scapy_packet, frame_number)
            
            # Check for CDP by MAC address and payload (enhanced detection)
            elif self._is_cdp_packet(scapy_packet):
                self.logger.debug(f"CDP packet detected by enhanced analysis at frame {frame_number}")
                return CDPPacket(scapy_packet, frame_number)
            
            # Check for ISL by characteristics
            elif self._is_isl_packet(scapy_packet):
                return ISLPacket(scapy_packet, frame_number)
            
            # Check for DTP by MAC
            elif self._is_dtp_packet(scapy_packet):
                return DTPPacket(scapy_packet, frame_number)
            
            # Default to base packet
            else:
                return BasePacket(scapy_packet, frame_number)
                
        except Exception as e:
            self.logger.warning(f"Error creating packet object for frame {frame_number}: {e}")
            return BasePacket(scapy_packet, frame_number)
    
    def _is_cdp_packet(self, scapy_packet) -> bool:
        """Check if packet is CDP using payload-based analysis without MAC dependency."""
        try:
            raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
            
            # Method 1: Check LLC/SNAP for CDP OUI and PID
            if scapy_packet.haslayer('LLC'):
                llc_layer = scapy_packet['LLC']
                if hasattr(llc_layer, 'dsap') and hasattr(llc_layer, 'ssap'):
                    if llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa:
                        # Check for CDP SNAP: OUI 00:00:0c and PID 0x2000
                        llc_payload = bytes(llc_layer.payload) if llc_layer.payload else b''
                        if len(llc_payload) >= 5:
                            if llc_payload[0:3] == b'\x00\x00\x0c' and llc_payload[3:5] == b'\x20\x00':
                                return True
            
            # Method 2: Search for CDP SNAP signature anywhere in payload
            for i in range(len(raw_payload) - 7):
                if (raw_payload[i:i+3] == b'\x00\x00\x0c' and 
                    raw_payload[i+3:i+5] == b'\x20\x00'):
                    # Validate CDP header follows
                    cdp_start = i + 5
                    if cdp_start + 2 < len(raw_payload):
                        version = raw_payload[cdp_start]
                        ttl = raw_payload[cdp_start + 1]
                        if version in [1, 2] and 1 <= ttl <= 255:
                            return True
            
            # Method 3: Look for CDP version/TTL pattern without SNAP
            for i in range(len(raw_payload) - 4):
                version = raw_payload[i]
                ttl = raw_payload[i + 1]
                if version in [1, 2] and 1 <= ttl <= 255:
                    # Additional validation: check for reasonable checksum position
                    if i + 4 <= len(raw_payload):
                        # Look ahead for TLV patterns (Type-Length-Value)
                        tlv_start = i + 4
                        valid_tlvs = 0
                        offset = tlv_start
                        
                        # Check for at least 2 valid TLV structures
                        while offset < len(raw_payload) - 4 and valid_tlvs < 3:
                            tlv_type = int.from_bytes(raw_payload[offset:offset+2], 'big')
                            tlv_length = int.from_bytes(raw_payload[offset+2:offset+4], 'big')
                            
                            # Valid CDP TLV types: 1-25
                            if 1 <= tlv_type <= 25 and 4 <= tlv_length <= 1500:
                                valid_tlvs += 1
                                offset += tlv_length
                            else:
                                break
                        
                        if valid_tlvs >= 2:
                            return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error in CDP detection: {e}")
            return False
    
    def _is_dtp_packet(self, scapy_packet) -> bool:
        """Check if packet is DTP using payload-based analysis without MAC dependency."""
        try:
            raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
            
            # Method 1: Check LLC/SNAP for DTP OUI and PID
            if scapy_packet.haslayer('LLC'):
                llc_layer = scapy_packet['LLC']
                if hasattr(llc_layer, 'dsap') and hasattr(llc_layer, 'ssap'):
                    if llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa:
                        # Check for DTP SNAP: OUI 00:00:0c and PID 0x2004
                        llc_payload = bytes(llc_layer.payload) if llc_layer.payload else b''
                        if len(llc_payload) >= 5:
                            if llc_payload[0:3] == b'\x00\x00\x0c' and llc_payload[3:5] == b'\x20\x04':
                                return True
            
            # Method 2: Search for DTP SNAP signature anywhere in payload
            for i in range(len(raw_payload) - 7):
                if (raw_payload[i:i+3] == b'\x00\x00\x0c' and 
                    raw_payload[i+3:i+5] == b'\x20\x04'):
                    # Validate DTP header follows
                    dtp_start = i + 5
                    if dtp_start + 4 < len(raw_payload):
                        # DTP has a version field (usually 1) at start
                        version = raw_payload[dtp_start]
                        if version == 1:
                            return True
            
            # Method 3: Look for DTP TLV patterns
            for i in range(len(raw_payload) - 8):
                # DTP TLVs have specific patterns
                if i + 8 <= len(raw_payload):
                    # Check for DTP TLV structure (Type-Length-Value)
                    tlv_type = int.from_bytes(raw_payload[i:i+2], 'big')
                    tlv_length = int.from_bytes(raw_payload[i+2:i+4], 'big')
                    
                    # DTP TLV types: 1 (Domain), 2 (Status), 3 (Type), 4 (Neighbor)
                    if tlv_type in [1, 2, 3, 4] and 4 <= tlv_length <= 100:
                        # Look for more DTP TLVs to confirm
                        valid_dtp_tlvs = 1
                        offset = i + tlv_length
                        
                        while offset < len(raw_payload) - 4 and valid_dtp_tlvs < 3:
                            next_type = int.from_bytes(raw_payload[offset:offset+2], 'big')
                            next_length = int.from_bytes(raw_payload[offset+2:offset+4], 'big')
                            
                            if next_type in [1, 2, 3, 4] and 4 <= next_length <= 100:
                                valid_dtp_tlvs += 1
                                offset += next_length
                            else:
                                break
                        
                        if valid_dtp_tlvs >= 2:
                            return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error in DTP detection: {e}")
            return False
    
    def _is_lldp_packet(self, scapy_packet) -> bool:
        """Check if packet is LLDP with enhanced payload analysis."""
        try:
            if scapy_packet.haslayer('Ether'):
                dst_mac = str(scapy_packet['Ether'].dst).lower()
                # Check for standard LLDP MAC addresses
                if dst_mac in ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']:
                    # Additional payload validation for LLDP
                    raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
                    if len(raw_payload) >= 4:
                        # Check for LLDP TLV structure
                        # First TLV should be Chassis ID (type 1) or Port ID (type 2)
                        first_tlv = int.from_bytes(raw_payload[0:2], 'big') if len(raw_payload) >= 2 else 0
                        tlv_type = (first_tlv >> 9) & 0x7F
                        tlv_length = first_tlv & 0x1FF
                        
                        # Valid LLDP should start with Chassis ID (1), Port ID (2), or TTL (3)
                        if tlv_type in [1, 2, 3] and 0 < tlv_length <= 255:
                            return True
                    # If MAC matches but payload doesn't look like LLDP, still consider it LLDP
                    return True
            return False
        except Exception as e:
            self.logger.debug(f"Error in LLDP detection: {e}")
            return False
    
    def _is_dtp_packet(self, scapy_packet) -> bool:
        """Check if packet is DTP."""
        try:
            if scapy_packet.haslayer('Ether'):
                dst_mac = str(scapy_packet['Ether'].dst).lower()
                if dst_mac in _CISCO_MACS and scapy_packet.haslayer('LLC'):
                    # Check if this is DTP and not CDP
                    raw_payload = bytes(scapy_packet.payload) if scapy_packet.payload else b''
                    if len(raw_payload) >= 8:
                        # DTP has different SNAP PID than CDP
                        # CDP: OUI 00:00:0c, PID 0x2000
                        # DTP: OUI 00:00:0c, PID 0x2004
                        return (raw_payload[3:6] == b'\x00\x00\x0c' and 
                               raw_payload[6:8] == b'\x20\x04')
                    return False
            return False
        except Exception as e:
            self.logger.debug(f"Error in DTP detection: {e}")
            return False
    
    def _is_vtp_packet(self, scapy_packet) -> bool:
        """Check if packet is VTP."""
        try:
            if scapy_packet.haslayer('LLC'):
                llc_layer = scapy_packet['LLC']
                return llc_layer.dsap == 0xaa and llc_layer.ssap == 0xaa
            return False
        except Exception:
            return False
    
    def _is_isl_packet(self, scapy_packet) -> bool:
        """Check if packet is ISL."""
        try:
            if scapy_packet.haslayer('Ether'):
                # ISL packets typically have specific characteristics
                if len(scapy_packet) > 30:  # ISL adds overhead
                    raw_data = bytes(scapy_packet)
                    # Check for ISL header pattern (simplified)
                    if len(raw_data) >= 26 and raw_data[0:4] == b'\x01\x00\x0c\x00':
                        return True
            return False
        except Exception:
            return False
    
    def _close_flow(self, flow_key: str):
        """Close a flow and move it to completed flows."""
        if flow_key in self.active_flows:
            flow = self.active_flows.pop(flow_key)
            flow.close_flow()
            self.completed_flows.append(flow)
            self.flow_stats['completed'] += 1
    
    def _cleanup_timed_out_flows(self):
        """Clean up flows that have timed out."""
        current_time = time.time()
        timed_out_flows = []
        
        # Create a copy of the items to avoid "dictionary changed size during iteration"
        for flow_key, flow in list(self.active_flows.items()):
            if flow.is_timeout(current_time, self.flow_timeout):
                timed_out_flows.append(flow_key)
        
        for flow_key in timed_out_flows:
            self._close_flow(flow_key)
            self.flow_stats['timed_out'] += 1
    
    def _cleanup_old_flows(self):
        """Clean up oldest flows when max_flows limit is reached."""
        if len(self.active_flows) >= self.max_flows:
            # Sort flows by last activity time and close oldest ones
            sorted_flows = sorted(
                self.active_flows.items(),
                key=lambda x: x[1].last_activity
            )
            
            # Close oldest 10% of flows
            flows_to_close = len(sorted_flows) // 10
            for i in range(flows_to_close):
                flow_key = sorted_flows[i][0]
                self._close_flow(flow_key)
                self.flow_stats['force_closed'] += 1
    
    def finalize_all_flows(self):
        """Close all remaining active flows."""
        # Create a copy of the keys to avoid "dictionary changed size during iteration"
        active_flow_keys = list(self.active_flows.keys())
        for flow_key in active_flow_keys:
            self._close_flow(flow_key)
    
    def get_all_flows(self) -> List[Flow]:
        """Get all flows (active and completed)."""
        return list(self.active_flows.values()) + self.completed_flows
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            'total_packets': self.total_packets_processed,
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'total_flows': len(self.active_flows) + len(self.completed_flows),
            'protocol_stats': dict(self.protocol_stats),
            'flow_stats': dict(self.flow_stats),
        }
    
    def get_batch_completed_flows(self, batch_size: int = 30) -> List[Flow]:
        """
        Get a batch of completed flows and remove them from memory.
        
        Args:
            batch_size: Number of flows to return in batch
            
        Returns:
            List of completed flows (up to batch_size)
        """
        if len(self.completed_flows) >= batch_size:
            batch_flows = self.completed_flows[:batch_size]
            self.completed_flows = self.completed_flows[batch_size:]
            self.logger.info(f"Retrieved batch of {len(batch_flows)} flows, {len(self.completed_flows)} remaining")
            return batch_flows
        elif self.completed_flows:
            # Return all remaining flows if less than batch_size
            batch_flows = self.completed_flows.copy()
            self.completed_flows.clear()
            self.logger.info(f"Retrieved final batch of {len(batch_flows)} flows")
            return batch_flows
        else:
            return []
    
    def clear_packet_data(self, flows: List[Flow]):
        """
        Clear packet data from flows to free memory while keeping flow features.
        
        Args:
            flows: List of flows to clear packet data from
        """
        for flow in flows:
            if hasattr(flow, 'packets') and flow.packets:
                # Ensure features are cached before clearing packets
                flow.get_features()  # This caches the features
                # Clear packet data to free memory
                flow.packets.clear()
        
        self.logger.debug(f"Cleared packet data from {len(flows)} flows")
    
    def force_flow_completion(self, max_active_flows: int = 100):
        """
        Force completion of oldest active flows when we need to free memory.
        
        Args:
            max_active_flows: Maximum number of active flows to keep
        """
        if len(self.active_flows) > max_active_flows:
            # Sort by last activity and force completion of oldest flows
            sorted_flows = sorted(
                self.active_flows.items(),
                key=lambda x: x[1].last_activity
            )
            
            flows_to_complete = len(self.active_flows) - max_active_flows
            for i in range(flows_to_complete):
                flow_key = sorted_flows[i][0]
                self._close_flow(flow_key)
                self.flow_stats['force_completed_for_memory'] += 1
            
            self.logger.info(f"Force completed {flows_to_complete} flows to manage memory")
    
    def get_memory_usage_estimate(self) -> dict:
        """
        Get estimated memory usage of flows.
        
        Returns:
            Dictionary with memory usage estimates
        """
        active_flows_mem = len(self.active_flows) * 1024  # Rough estimate
        completed_flows_mem = len(self.completed_flows) * 1024
        
        # More detailed estimation based on packets
        total_packets = sum(len(flow.packets) for flow in self.active_flows.values())
        total_packets += sum(len(flow.packets) for flow in self.completed_flows)
        packet_mem = total_packets * 500  # Rough estimate per packet
        
        return {
            'active_flows': len(self.active_flows),
            'completed_flows': len(self.completed_flows),
            'total_packets_in_memory': total_packets,
            'estimated_memory_mb': (active_flows_mem + completed_flows_mem + packet_mem) / 1024 / 1024
        }

    def log_progress(self):
        """Log current processing progress with detailed protocol breakdown."""
        stats = self.get_statistics()
        
        # Create detailed protocol summary
        protocol_items = []
        for proto, count in sorted(stats['protocol_stats'].items()):
            if count > 0:
                protocol_items.append(f"{count} {proto}")
        
        protocol_summary = ', '.join(protocol_items) if protocol_items else 'no packets processed'
        
        # Special logging for CDP to debug detection
        cdp_count = stats['protocol_stats'].get('CDP', 0)
        if cdp_count > 0:
            self.logger.info(f"CDP Detection: Found {cdp_count} CDP packets")
        
        self.logger.info(
            f"Processed {stats['total_packets']} packets: {protocol_summary} "
            f"with {stats['total_flows']} flows ({stats['active_flows']} active, "
            f"{stats['completed_flows']} completed)"
        )