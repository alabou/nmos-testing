# Copyright (C) 2025 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import struct
import time
import ipaddress
import platform
import subprocess
import re
import random
from typing import Optional, Tuple
from . import Config as CONFIG
import ctypes
import psutil

AF_INET = 2
AF_INET6 = 23

class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p),
                ("iSockaddrLength", ctypes.c_int)]

class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass

LP_IP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)
IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", LP_IP_ADAPTER_UNICAST_ADDRESS),
    ("Address", SOCKET_ADDRESS)
]

class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass

LP_IP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", LP_IP_ADAPTER_ADDRESSES),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", LP_IP_ADAPTER_UNICAST_ADDRESS),
    ("FirstAnycastAddress", ctypes.c_void_p),  # LP_IP_ADAPTER_ANYCAST_ADDRESS
    ("FirstMulticastAddress", ctypes.c_void_p),  # LP_IP_ADAPTER_MULTICAST_ADDRESS
    ("FirstDnsServerAddress", ctypes.c_void_p),  # LP_IP_ADAPTER_DNS_SERVER_ADDRESS
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
]

GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.argtypes = [
    ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
    LP_IP_ADAPTER_ADDRESSES, ctypes.POINTER(ctypes.c_ulong)
]

GAA_FLAG_SKIP_ANYCAST   = 0x2
GAA_FLAG_SKIP_MULTICAST = 0x4
GAA_FLAG_SKIP_DNS_SERVER= 0x8
GAA_FLAG_INCLUDE_PREFIX = 0x10

class MulticastJoinError(Exception):
    """Exception raised when multicast join operations fail"""
    pass


class MulticastUtils:
    """Utility class for multicast operations including IGMP v3 joins with source filtering"""

    # -----------------------------
    # Helpers
    # -----------------------------
    @staticmethod
    def get_windows_adapters():
        size = ctypes.c_ulong(16384)
        while True:
            buf = ctypes.create_string_buffer(size.value)
            rc = GetAdaptersAddresses(
                AF_INET,  # request at least IPv4; we also harvest v6 from the list
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX,
                None,
                ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES),
                ctypes.byref(size)
            )
            if rc == 0:
                break
            if rc == 111:  # ERROR_BUFFER_OVERFLOW
                continue
            raise OSError(f"GetAdaptersAddresses failed: {rc}")
        adapters = ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES)
        res = []
        while adapters:
            ad = adapters.contents
            ips = []
            uni = ad.FirstUnicastAddress
            while uni:
                sa = uni.contents.Address
                p = ctypes.cast(sa.lpSockaddr, ctypes.POINTER(ctypes.c_ubyte * sa.iSockaddrLength)).contents
                family = p[0] | (p[1] << 8)
                if family == AF_INET:
                    ips.append(socket.inet_ntoa(bytes(p[4:8])))
                elif family == AF_INET6:
                    raw = bytes(p[8:24])
                    ip6 = socket.inet_ntop(socket.AF_INET6, raw)
                    ips.append(ip6)
                uni = uni.contents.Next
            # AdapterName is like b'{GUID}', FriendlyName is human name
            guid = (ad.AdapterName or b"").decode(errors="ignore").strip()
            guid = guid.strip("{}")
            res.append({
                "name": ad.FriendlyName or "",
                "guid": guid.upper(),
                "ips": ips,
                "if_index": int(ad.IfIndex),
            })
            adapters = ad.Next
        return res
        
    @staticmethod
    def _set_multicast_if(sock: socket.socket, interface_ip: str) -> None:
        """Set the outgoing/interface for multicast membership ops (best-effort)."""
        try:
            if interface_ip and interface_ip != "0.0.0.0":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
        except OSError:
            # Not fatal; some stacks don't require it
            pass

    @staticmethod
    def is_multicast_address(ip: str) -> bool:
        """Check if the given IP address is a valid multicast address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                return ip_obj.is_multicast
            elif ip_obj.version == 6:
                return ip_obj.is_multicast
            return False
        except ValueError:
            return False

    @staticmethod
    def is_valid_admin_scope_multicast(ip: str) -> bool:
        """Check if the given IP address is a valid admin scope multicast address (239.0.0.0/8)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4 and ip_obj.is_multicast:
                # Check if it's in the admin scope range (239.0.0.0 - 239.255.255.255)
                return ip.split('.')[0] == '239'
            return False
        except ValueError:
            return False

    @staticmethod
    def getRandomIpv4AddressWithinRange(start_ip: str, end_ip: str) -> str:
        """Generate a random IPv4 address within the given IP range (inclusive)"""
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)

            if start.version != 4 or end.version != 4:
                raise ValueError("Only IPv4 addresses are supported")

            if start > end:
                raise ValueError("Start IP must be less than or equal to end IP")

            # Convert to integers for random selection
            start_int = int(start)
            end_int = int(end)

            # Generate random IP within range
            random_int = random.randint(start_int, end_int)
            random_ip = ipaddress.ip_address(random_int)

            return str(random_ip)

        except ValueError as e:
            raise ValueError(f"Invalid IP range: {e}")

    @staticmethod
    def get_interface_ip() -> str:
        """Get the default interface IP address for multicast operations"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 80))
                return s.getsockname()[0]
        except Exception:
            return "0.0.0.0"

    @staticmethod
    def get_configured_interface() -> Optional[str]:
        """Get the configured multicast interface from Config.py"""
        return getattr(CONFIG, 'MULTICAST_INTERFACE', None)

    @staticmethod
    def get_windows_interface_ip(interface_name: str) -> Optional[str]:
        """
        Get IP address for a Windows interface name using ipconfig
        """
        if interface_name is None or interface_name == "":
            return None

        try:
            interfaces = MulticastUtils.get_windows_adapters()

            for interface in interfaces:
                if interface_name in interface['ips']:
                    return interface_name  # which is an IP address
                if interface_name == interface['name']:
                    return interface['ips'][0]  # return the first one

        except Exception as e:
            print(f"Warning: Failed to query Windows interface {interface_name}: {e}")

        return None

    @staticmethod
    def get_linux_interface_ip(interface_name: str) -> Optional[str]:
        """
        Get IP address for a Linux interface name using psutil
        """
        if interface_name is None or interface_name == "":
            return None
            
        try:
            # Check if interface_name is already an IP address
            try:
                ipaddress.ip_address(interface_name)
                return interface_name
            except ValueError:
                pass

            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            
            if interface_name in interfaces:
                addrs = interfaces[interface_name]
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        return addr.address
        except Exception as e:
            print(f"Warning: Failed to query Linux interface {interface_name}: {e}")

        return None

    @staticmethod
    def get_windows_interface_NPF(interface_name: str) -> Optional[str]:
        """
        Get NPF device path for a Windows interface name or IP address.
        Returns NPF_Loopback for loopback addresses (127.0.0.1 or localhost).
        """
        # Handle loopback addresses
        if interface_name == "127.0.0.1" or interface_name.lower() == "localhost":
            return "\\Device\\NPF_Loopback"
        
        try:
            interfaces = MulticastUtils.get_windows_adapters()

            for interface in interfaces:
                if interface_name in interface['ips']:
                    return f"\\Device\\NPF_{{{interface['guid']}}}"
                if interface_name == interface['name']:
                    return f"\\Device\\NPF_{{{interface['guid']}}}"

        except Exception as e:
            print(f"Warning: Failed to query Windows interface {interface_name}: {e}")

        return None

    @staticmethod
    def get_best_interface_for_destination(dest_ip: str) -> str:
        """Determine the best local interface to reach dest_ip"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((dest_ip, 80))
                return s.getsockname()[0]
        except Exception:
            return MulticastUtils.get_interface_ip()

    @staticmethod
    def interface_name_to_ip(interface_name: str) -> str:
        """Convert network interface name to IP address"""
        if platform.system() == "Windows":
            windows_ip = MulticastUtils.get_windows_interface_ip(interface_name)
            if windows_ip:
                return windows_ip
        else:
            linux_ip = MulticastUtils.get_linux_interface_ip(interface_name)
            if linux_ip:
                return linux_ip

        interface_map = {
            'lo': '127.0.0.1',
            'localhost': '127.0.0.1',
            'loopback': '127.0.0.1',
        }

        if platform.system() == "Windows":
            interface_map.update({
                'eth0': '0.0.0.0',
                'wlan0': '0.0.0.0',
                'any': '0.0.0.0',
                'ethernet': '0.0.0.0',
                'wi-fi': '0.0.0.0',
            })
        else:
            interface_map.update({
                'eth0': '0.0.0.0',
                'wlan0': '0.0.0.0',
                'any': '0.0.0.0',
            })

        if interface_name in interface_map:
            return interface_map[interface_name]
        else:
            if platform.system() == "Windows":
                raise MulticastJoinError(
                    f"Windows interface '{interface_name}' not found. "
                    f"Use 'ipconfig /all' to see available interfaces, "
                    f"or try: {list(interface_map.keys())}"
                )
            else:
                raise MulticastJoinError(
                    f"Interface {interface_name} not supported. "
                    f"Supported interfaces: {list(interface_map.keys())}"
                )

    @staticmethod
    def resolve_interface_param(interface_param: Optional[str], source_ip: Optional[str] = None) -> str:
        """Resolve interface parameter to IP address with intelligent selection"""

        if interface_param is not None:
            try:
                ipaddress.ip_address(interface_param)
                return interface_param
            except ValueError:
                return MulticastUtils.interface_name_to_ip(interface_param)

        configured_interface = MulticastUtils.get_configured_interface()
        if configured_interface is not None:
            try:
                ipaddress.ip_address(configured_interface)
                return configured_interface
            except ValueError:
                return MulticastUtils.interface_name_to_ip(configured_interface)

        if source_ip is not None:
            try:
                best_interface = MulticastUtils.get_best_interface_for_destination(source_ip)
                if best_interface != "0.0.0.0":
                    return best_interface
            except Exception:
                pass

        return MulticastUtils.get_interface_ip()

    # -----------------------------
    # Join (IGMPv3 SSM)
    # -----------------------------

    @staticmethod
    def join_multicast_group_igmpv3(
        multicast_ip: str,
        source_ip: str,
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> Tuple[socket.socket, str]:
        """Join a multicast group using IGMP v3 with source filtering

        Returns:
            Tuple[socket.socket, str]: The socket and the resolved interface IP used for joining
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")

        interface_ip = MulticastUtils.resolve_interface_param(interface_name, source_ip)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            if platform.system() == "Windows":
                try:
                    sock.bind(('', port))
                except Exception:
                    sock.bind((multicast_ip, port))
            else:
                sock.bind(('', port))

            MulticastUtils._set_multicast_if(sock, interface_ip)

            # ASM membership
            if interface_ip == "0.0.0.0":
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   struct.pack("!I", socket.INADDR_ANY))
            else:
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   socket.inet_aton(interface_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # SSM membership (ip_mreq_source: group, source, iface)
            try:
                source_mreq = struct.pack(
                    "4s4s4s",
                    socket.inet_aton(multicast_ip),
                    socket.inet_aton(source_ip),
                    socket.inet_aton(interface_ip) if interface_ip != "0.0.0.0"
                    else struct.pack("!I", socket.INADDR_ANY),
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, source_mreq)
            except (OSError, AttributeError):
                print(f"Warning: Source filtering not supported on this system. "
                      f"Joining multicast group {multicast_ip} without source filtering.")

            return sock, interface_ip

        except Exception as e:
            if 'sock' in locals():
                try:
                    sock.close()
                except Exception:
                    pass
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Join (ASM simple)
    # -----------------------------

    @staticmethod
    def join_multicast_group_simple(
        multicast_ip: str,
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> Tuple[socket.socket, str]:
        """Join a multicast group using simple IGMP (ASM)

        Returns:
            Tuple[socket.socket, str]: The socket and the resolved interface IP used for joining
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")

        interface_ip = MulticastUtils.resolve_interface_param(interface_name)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            if platform.system() == "Windows":
                try:
                    sock.bind(('', port))
                except Exception:
                    sock.bind((multicast_ip, port))
            else:
                sock.bind(('', port))

            MulticastUtils._set_multicast_if(sock, interface_ip)

            if interface_ip == "0.0.0.0":
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   struct.pack("!I", socket.INADDR_ANY))
            else:
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   socket.inet_aton(interface_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            return sock, interface_ip

        except Exception as e:
            if 'sock' in locals():
                try:
                    sock.close()
                except Exception:
                    pass
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Leave
    # -----------------------------

    @staticmethod
    def leave_multicast_group(sock: socket.socket, multicast_ip: str, interface_ip: str):
        """
        Leave a multicast group using the exact interface IP that was used for joining.

        Args:
            sock: The socket to leave from
            multicast_ip: The multicast group IP
            interface_ip: The resolved interface IP that was used for joining (returned by join methods)
        """
        try:
            # Use the exact same interface IP that was used for joining
            if interface_ip == "0.0.0.0":
                mreq = struct.pack(
                    "4s4s",
                    socket.inet_aton(multicast_ip),
                    struct.pack("!I", socket.INADDR_ANY),
                )
            else:
                mreq = struct.pack(
                    "4s4s",
                    socket.inet_aton(multicast_ip),
                    socket.inet_aton(interface_ip),
                )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)

            # Optional best-effort: attempt to drop any SSM memberships too
            try:
                drop_src_any = struct.pack(
                    "4s4s4s",
                    socket.inet_aton(multicast_ip),
                    struct.pack("!I", socket.INADDR_ANY),  # ANY source
                    struct.pack("!I", socket.INADDR_ANY),  # ANY interface
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_SOURCE_MEMBERSHIP, drop_src_any)
            except (OSError, AttributeError):
                # Either unsupported or requires exact source; safe to ignore.
                pass

        except Exception as e:
            print(f"Warning: Failed to leave multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Misc
    # -----------------------------

    @staticmethod
    def is_local_ip(ip: str) -> bool:
        """Check if the provided IP is assigned to a local interface."""
        try:
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            return ip in local_ips or ip == "127.0.0.1"
        except Exception:
            return False

    @staticmethod
    def receive_multicast_data(sock: socket.socket, buffer_size: int = 4096) -> Tuple[bytes, str]:
        """Receive data from a multicast socket"""
        try:
            data, addr = sock.recvfrom(buffer_size)
            return data, addr[0]
        except socket.timeout:
            return b"", ""
        except Exception as e:
            raise MulticastJoinError(f"Failed to receive multicast data: {e}")

    @staticmethod
    def test_multicast_connectivity(
        multicast_ip: str,
        source_ip: str,
        port: int,
        duration: int = 5,
        interface_name: Optional[str] = None
    ) -> bool:
        """Test multicast connectivity by joining the group and listening for data"""
        sock = None
        interface_ip = None
        try:
            # Try IGMP v3 with source filtering first
            try:
                sock, interface_ip = MulticastUtils.join_multicast_group_igmpv3(
                    multicast_ip, source_ip, port, interface_name=interface_name
                )
                print(f"Successfully joined multicast group {multicast_ip} with source filtering for {source_ip}")
            except MulticastJoinError:
                # Fallback to simple multicast join
                sock, interface_ip = MulticastUtils.join_multicast_group_simple(
                    multicast_ip, port, interface_name=interface_name
                )
                print(f"Successfully joined multicast group {multicast_ip} (without source filtering)")

            # Listen for data
            start_time = time.time()
            data_received = False

            while time.time() - start_time < duration:
                data, source = MulticastUtils.receive_multicast_data(sock, 1024)
                if data:
                    print(f"Received {len(data)} bytes from {source}")
                    data_received = True
                    break

            return data_received

        except Exception as e:
            print(f"Multicast connectivity test failed: {e}")
            return False
        finally:
            if sock and interface_ip is not None:
                MulticastUtils.leave_multicast_group(sock, multicast_ip, interface_ip)
                sock.close()
