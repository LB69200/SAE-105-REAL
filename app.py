import matplotlib
matplotlib.use('Agg')  # Set backend to non-interactive mode
from flask import Flask, render_template, jsonify, request
import json
from packet_analyzer import PacketAnalyzer, NetworkPacket
import os
from datetime import datetime

app = Flask(__name__)
packet_analyzer = PacketAnalyzer()

def serialize_attacker(attacker_dict):
    """Convertit les sets en listes pour la sérialisation JSON"""
    result = {}
    for key, value in attacker_dict.items():
        if isinstance(value, set):
            result[key] = list(value)
        else:
            result[key] = value
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_data():
    data = request.get_json()
    if 'packets' in data:
        for packet_data in data['packets']:
            packet = NetworkPacket(
                source_ip=packet_data['source_ip'],
                destination_ip=packet_data['destination_ip'],
                flags=packet_data['flags'],
                length=packet_data['length'],
                timestamp=packet_data['timestamp'],
                port=packet_data.get('port')
            )
            packet_analyzer.analyze_packet(packet)
        
        # Get analysis data
        summary = packet_analyzer.get_summary()
        attackers = [serialize_attacker(vars(attacker)) for attacker in packet_analyzer.get_attackers()]
        
        # Include packet sizes in the response
        packet_sizes = packet_analyzer.packet_sizes
        
        return jsonify({
            'status': 'success',
            'summary': summary,
            'attackers': attackers,
            'packet_sizes': packet_sizes  # Add this line
        })
    return jsonify({'status': 'error', 'message': 'No packet data provided'})

@app.route('/get_analysis')
def get_analysis():
    summary = packet_analyzer.get_summary()
    attackers = [serialize_attacker(vars(attacker)) for attacker in packet_analyzer.get_attackers()]
    return jsonify({
        'summary': summary,
        'attackers': attackers,
        'packet_sizes': packet_analyzer.packet_sizes  # Add this line
    })

if __name__ == '__main__':
    app.run(debug=True)