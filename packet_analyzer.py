from dataclasses import dataclass
from typing import List, Dict, Optional, Set
import re
import statistics
from datetime import datetime
import os
import matplotlib
matplotlib.use('Agg')  # Pour éviter les problèmes de GUI
import matplotlib.pyplot as plt
from collections import defaultdict

@dataclass
class NetworkPacket:
    """Représente un paquet réseau"""
    source_ip: str
    destination_ip: str
    flags: str
    length: int
    timestamp: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    seq_info: Optional[str] = None
    win_info: Optional[str] = None
    options: Optional[str] = None
    hex_dump: Optional[str] = None

@dataclass
class AttackerProfile:
    """Profile d'un attaquant potentiel"""
    ip_address: str
    hostname: str
    packet_count: int
    avg_packet_size: float
    syn_count: int
    unique_ports_targeted: int
    attack_type: str
    original_ips: Set[str]

class AttackAnalyzer:
    """Analyse les attaques potentielles"""
    def __init__(self):
        self._syn_flood_threshold = 10
        self._port_scan_threshold = 5
        
        self.attackers = defaultdict(lambda: {
            'packets': [],
            'packet_sizes': [],
            'syn_count': 0,
            'ports_targeted': set(),
            'hostname': 'Unknown',
            'original_ips': set()
        })

    def _determine_attack_type(self, syn_count: int, unique_ports: int, avg_packet_size: float) -> str:
        """Détermine le type d'attaque basé sur les caractéristiques observées"""
        attack_types = []
        
        if unique_ports >= self._port_scan_threshold:
            attack_types.append("Port Scan")
            
        if syn_count >= self._syn_flood_threshold:
            attack_types.append("DDoS (SYN Flood)")
        elif syn_count >= self._syn_flood_threshold // 20:
            attack_types.append("Potential SYN Flood")
            
        if avg_packet_size > 1000 and syn_count > self._syn_flood_threshold // 10:
            attack_types.append("Suspicious Large Packets")
            
        return " + ".join(attack_types) if attack_types else "Suspicious Activity"

    def analyze_packet(self, packet: NetworkPacket):
        """Analyse un paquet pour détecter des comportements suspects"""
        attacker = self.attackers[packet.source_ip]
        
        if packet.flags and ('S' in packet.flags and '.' not in packet.flags):
            attacker['syn_count'] += 1
            
        if packet.port:
            attacker['ports_targeted'].add(packet.port)
            
        attacker['packet_sizes'].append(packet.length)
        attacker['hostname'] = packet.source_ip
        attacker['original_ips'].add(packet.source_ip)
        attacker['packets'].append(packet)

class PacketAnalyzer:
    """Analyseur principal des paquets réseaux"""
    def __init__(self):
        self.packets: List[NetworkPacket] = []
        self.tcp_flags = defaultdict(int)
        self.packet_sizes = []
        self.total_packets = 0
        self.attack_analyzer = AttackAnalyzer()

    def parse_packet(self, line: str) -> Optional[NetworkPacket]:
        """Parse une ligne de tcpdump et retourne un objet NetworkPacket"""
        # Ignore les lignes hex
        if not line.strip() or line.startswith('\t0x'):
            return None

        # Patterns plus précis pour l'extraction
        timestamp_pattern = r'^(\d{2}:\d{2}:\d{2}\.\d{6})'
        ip_pattern = r'IP ([^ ]+) > ([^:]+)'
        flags_pattern = r'Flags \[(.*?)\]'
        length_pattern = r'length (\d+)'
        port_pattern = r'\.(\d+)'
        seq_pattern = r'seq (\d+:\d+|\d+)'
        win_pattern = r'win (\d+)'
        options_pattern = r'options \[(.*?)\]'

        try:
            timestamp = re.search(timestamp_pattern, line)
            ip_match = re.search(ip_pattern, line)
            flags = re.search(flags_pattern, line)
            length = re.search(length_pattern, line)
            seq = re.search(seq_pattern, line)
            win = re.search(win_pattern, line)
            options = re.search(options_pattern, line)

            if timestamp and ip_match:
                # Extraction de l'IP source et de destination
                source = ip_match.group(1)
                destination = ip_match.group(2)
                
                # Extraction des ports
                source_port = None
                if '.' in source:
                    source_port = int(source.split('.')[-1])
                    source = source.split('.')[0]

                # Nettoyage des noms d'hôtes si présents
                source_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', source)
                dest_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', destination)

                if source_ip and dest_ip:
                    packet = NetworkPacket(
                        source_ip=source_ip.group(1),
                        destination_ip=dest_ip.group(1),
                        flags=flags.group(1) if flags else '',
                        length=int(length.group(1)) if length else 0,
                        timestamp=timestamp.group(1),
                        port=source_port,
                        seq_info=seq.group(1) if seq else None,
                        win_info=win.group(1) if win else None,
                        options=options.group(1) if options else None
                    )
                    return packet
        except Exception as e:
            print(f"Erreur lors du parsing du paquet: {e}")
            print(f"Ligne problématique: {line}")
        return None

    def analyze_packet(self, packet: NetworkPacket):
        """Analyse un paquet réseau"""
        if not packet:
            return

        self.total_packets += 1
        self.packet_sizes.append(packet.length)

        # Analyse des flags
        if packet.flags:
            flag_type = self._determine_flag_type(packet.flags)
            self.tcp_flags[flag_type] += 1

            # Détection des paquets suspects
            if 'S' in packet.flags and '.' not in packet.flags:
                self.attack_analyzer.analyze_packet(packet)

    def _determine_flag_type(self, flags: str) -> str:
        """Détermine le type de flag TCP"""
        flags = flags.upper()
        if 'S' in flags and '.' in flags:
            return 'SYN-ACK'
        elif 'S' in flags:
            return 'SYN'
        elif 'P' in flags and '.' in flags:
            return 'PUSH-ACK'
        elif 'F' in flags and '.' in flags:
            return 'FIN-ACK'
        elif 'R' in flags:
            return 'RST'
        elif '.' in flags:
            return 'ACK'
        return flags

    def get_summary(self) -> Dict:
        """Retourne un résumé de l'analyse"""
        if not self.packet_sizes:
            return {
                'total_packets': 0,
                'unique_sizes': 0,
                'avg_size': 0,
                'tcp_flags': {}
            }
        
        return {
            'total_packets': self.total_packets,
            'unique_sizes': len(set(self.packet_sizes)),
            'avg_size': statistics.mean(self.packet_sizes),
            'tcp_flags': dict(self.tcp_flags)
        }

    def get_attackers(self) -> List[AttackerProfile]:
        """Retourne la liste des attaquants potentiels"""
        profiles = []
        for ip, data in self.attack_analyzer.attackers.items():
            if not data['packets']:
                continue
                
            avg_size = statistics.mean(data['packet_sizes']) if data['packet_sizes'] else 0
            profile = AttackerProfile(
                ip_address=ip,
                hostname=data['hostname'],
                packet_count=len(data['packets']),
                avg_packet_size=avg_size,
                syn_count=data['syn_count'],
                unique_ports_targeted=len(data['ports_targeted']),
                attack_type=self.attack_analyzer._determine_attack_type(
                    data['syn_count'],
                    len(data['ports_targeted']),
                    avg_size
                ),
                original_ips=data['original_ips']
            )
            profiles.append(profile)
            
        return sorted(profiles, key=lambda x: x.packet_count, reverse=True)

    def generate_visualizations(self, output_dir: str):
        """Génère les visualisations de l'analyse"""
        os.makedirs(output_dir, exist_ok=True)

        # Distribution des tailles de paquets
        plt.figure(figsize=(12, 6))
        if self.packet_sizes:
            plt.hist(self.packet_sizes, bins=50, color='skyblue', edgecolor='black')
            plt.title('Distribution des tailles de paquets')
            plt.xlabel('Taille (octets)')
            plt.ylabel('Nombre de paquets')
            plt.grid(True, alpha=0.3)
            plt.savefig(os.path.join(output_dir, 'packet_sizes.png'))
            plt.close()

        # Distribution des flags TCP
        plt.figure(figsize=(10, 10))
        if self.tcp_flags:
            sizes = list(self.tcp_flags.values())
            labels = list(self.tcp_flags.keys())
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            plt.title('Distribution des Flags TCP')
            plt.axis('equal')
            plt.savefig(os.path.join(output_dir, 'tcp_flags.png'))
            plt.close()