// Fonctions d'extraction
function extractTimestamp(line) {
    const match = line.match(/^(\d{2}:\d{2}:\d{2}\.\d{6})/);
    return match ? match[1] : null;
}

function extractProtocol(line) {
    const protocols = ['TCP', 'UDP', 'ICMP', 'IP'];
    for (const protocol of protocols) {
        if (line.includes(protocol)) {
            return protocol;
        }
    }
    return null;
}

function extractSeqInfo(line) {
    const seqMatch = line.match(/seq (\d+:\d+|\d+)/);
    return seqMatch ? seqMatch[1] : null;
}

function extractWinInfo(line) {
    const winMatch = line.match(/win (\d+)/);
    return winMatch ? winMatch[1] : null;
}

function extractSourceIP(line) {
    // Afficher la ligne pour le debug
    console.log("Ligne à analyser pour IP source:", line);
    
    // Chercher l'adresse IP après "IP" et avant ">"
    const ipMatch = line.match(/IP (?:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|([^ >]+))(?:\.([0-9]+))? >/);
    
    if (ipMatch) {
        if (ipMatch[1]) {
            // Si on a trouvé une IPv4
            console.log("IPv4 source trouvée:", ipMatch[1]);
            return ipMatch[1];
        } else if (ipMatch[2]) {
            // Si on a un hostname
            const ipInHostname = ipMatch[2].match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
            if (ipInHostname) {
                console.log("IPv4 trouvée dans le hostname:", ipInHostname[1]);
                return ipInHostname[1];
            }
            // Si c'est un hostname du type "190-0-175-100.gba.solunet.com.ar"
            const formattedHostname = ipMatch[2].match(/(\d+-\d+-\d+-\d+)/);
            if (formattedHostname) {
                const ip = formattedHostname[1].replace(/-/g, '.');
                console.log("IPv4 construite depuis le hostname:", ip);
                return ip;
            }
            
            // Pour les hostnames comme "BP-Linux8"
            const hostname = ipMatch[2].split('.')[0];  // Prend la première partie du hostname
            console.log("Hostname trouvé:", hostname);
            return hostname;
        }
    }
    
    console.log("Aucune IP/hostname source trouvé");
    return null;
}

function extractDestIP(line) {
    // Afficher la ligne pour le debug
    console.log("Ligne à analyser pour IP dest:", line);
    
    // Chercher le motif IP après ">"
    const parts = line.split(' > ');
    if (parts.length < 2) {
        console.log("Pas de séparateur '>' trouvé");
        return null;
    }
    
    const destPart = parts[1];
    console.log("Partie destination:", destPart);
    
    // Chercher une IPv4
    const ipv4Match = destPart.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
    if (ipv4Match) {
        console.log("IPv4 destination trouvée:", ipv4Match[1]);
        return ipv4Match[1];
    }
    
    // Si c'est un hostname, essayer de le récupérer
    const hostnameMatch = destPart.match(/^([^:.\s]+)/);
    if (hostnameMatch) {
        console.log("Hostname destination trouvé:", hostnameMatch[1]);
        return hostnameMatch[1];
    }
    
    console.log("Aucune IP/hostname destination trouvé");
    return null;
}

function extractFlags(line) {
    const flagsMatch = line.match(/Flags \[(.*?)\]/i);
    if (flagsMatch) return flagsMatch[1];
    
    const individualFlags = line.match(/\b([SFRPAUEW.]+)\b/g);
    return individualFlags ? individualFlags.join('') : '';
}

function extractLength(line) {
    const lengthMatch = line.match(/length (\d+)/i);
    if (lengthMatch) return parseInt(lengthMatch[1]);
    
    const bytesMatch = line.match(/(\d+) bytes/i);
    return bytesMatch ? parseInt(bytesMatch[1]) : 0;
}

function extractPort(line) {
    const ports = line.match(/\.(\d+)/g);
    return ports && ports.length > 1 ? parseInt(ports[1].substring(1)) : null;
}

// Fonction de parsing principale
function parsePackets(text) {
    const packets = [];
    let currentPacket = null;
    let hexDump = [];
    let continuationLines = [];
    
    console.log("Début du parsing");
    const lines = text.split('\n');
    console.log(`Nombre total de lignes: ${lines.length}`);
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        // Nouvelle entrée de paquet (commence par un timestamp)
        if (line.match(/^\d{2}:\d{2}:\d{2}\.\d{6}/)) {
            // Sauvegarder le paquet précédent s'il existe
            if (currentPacket) {
                if (hexDump.length > 0) {
                    currentPacket.hex_dump = hexDump.join('\n');
                }
                if (continuationLines.length > 0) {
                    currentPacket.continuation = continuationLines.join('\n');
                }
                packets.push(currentPacket);
                hexDump = [];
                continuationLines = [];
            }
            
            const timestamp = extractTimestamp(line);
            const sourceIP = extractSourceIP(line);
            const destIP = extractDestIP(line);
            
            currentPacket = {
                timestamp: timestamp,
                source_ip: sourceIP || "unknown",  // utiliser "unknown" au lieu de null
                destination_ip: destIP,
                flags: extractFlags(line) || '',
                length: extractLength(line) || 0,
                port: extractPort(line),
                protocol: extractProtocol(line),
                seq_info: extractSeqInfo(line),
                win_info: extractWinInfo(line),
                raw_line: line  // garder la ligne brute pour debug
            };

            console.log(`Paquet #${packets.length + 1}:`, {
                timestamp: timestamp,
                source: sourceIP,
                dest: destIP,
                flags: currentPacket.flags,
                length: currentPacket.length
            });

        } else if (line.match(/^\s*0x[0-9a-f]+:/i)) {
            // Ligne hexadécimale
            hexDump.push(line);
        } else if (currentPacket) {
            // Lignes qui font partie du paquet courant
            continuationLines.push(line);
            
            // Essayer d'extraire des informations supplémentaires
            const additionalFlags = extractFlags(line);
            if (additionalFlags) {
                currentPacket.flags = currentPacket.flags ? 
                    currentPacket.flags + additionalFlags : 
                    additionalFlags;
            }
            
            const additionalLength = extractLength(line);
            if (additionalLength && (!currentPacket.length || currentPacket.length === 0)) {
                currentPacket.length = additionalLength;
            }
            
            if (line.includes('seq')) {
                currentPacket.seq_info = extractSeqInfo(line);
            }
            if (line.includes('win')) {
                currentPacket.win_info = extractWinInfo(line);
            }
        }
    }
    
    // Ne pas oublier le dernier paquet
    if (currentPacket) {
        if (hexDump.length > 0) {
            currentPacket.hex_dump = hexDump.join('\n');
        }
        if (continuationLines.length > 0) {
            currentPacket.continuation = continuationLines.join('\n');
        }
        packets.push(currentPacket);
    }
    
    console.log("Statistiques de parsing:");
    console.log(`- Total lignes traitées: ${lines.length}`);
    console.log(`- Paquets trouvés: ${packets.length}`);
    console.log(`- Paquets avec IP source inconnue: ${packets.filter(p => p.source_ip === "unknown").length}`);
    console.log(`- Paquets avec dumps hex: ${packets.filter(p => p.hex_dump).length}`);
    console.log(`- Paquets avec continuation: ${packets.filter(p => p.continuation).length}`);
    
    return packets;
}

// Fonction principale d'analyse
async function startAnalysis() {
    const fileInput = document.getElementById('packetFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Veuillez sélectionner un fichier');
        return;
    }

    console.log("Début de l'analyse du fichier:", file.name);
    console.log("Taille du fichier:", file.size, "octets");

    try {
        const text = await file.text();
        console.log("Fichier lu avec succès. Nombre de caractères:", text.length);
        
        const packets = parsePackets(text);
        
        // Stats avant envoi
        console.log("Statistiques avant envoi au serveur:");
        console.log("- Total paquets:", packets.length);
        console.log("- Paquets avec flags SYN:", packets.filter(p => p.flags.includes('S')).length);
        console.log("- Taille moyenne des paquets:", 
            (packets.reduce((sum, p) => sum + p.length, 0) / packets.length).toFixed(2));
        
        const response = await fetch('/upload', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                packets: packets,
                metadata: {
                    filename: file.name,
                    filesize: file.size,
                    packet_count: packets.length,
                    timestamp: new Date().toISOString()
                }
            })
        });

        const data = await response.json();
        console.log("Réponse du serveur:", data);
        
        if (data.status === 'success') {
            currentData = data;
            updateDashboard(data);
            
            // Log des statistiques d'attaque
            if (data.attackers && data.attackers.length > 0) {
                console.log("Attaques détectées:");
                data.attackers.forEach(attacker => {
                    console.log(`- ${attacker.ip_address}: ${attacker.attack_type}`);
                    console.log(`  * Paquets: ${attacker.packet_count}`);
                    console.log(`  * Ports ciblés: ${attacker.unique_ports_targeted}`);
                });
            }
        } else {
            alert('Erreur lors de l\'analyse: ' + data.message);
        }
    } catch (error) {
        console.error('Erreur lors de l\'analyse:', error);
        alert('Une erreur est survenue lors de l\'analyse\n' + error.message);
    }
}

// Fonctions de mise à jour de l'interface
function updateDashboard(data) {
    updateSummaryStats(data.summary);
    updateTCPFlagsChart(data.summary.tcp_flags);
    updatePacketSizesChart(data.packet_sizes);
    updateAttackersList(data.attackers);
}

function updateSummaryStats(summary) {
    const statsContainer = document.getElementById('summaryStats');
    statsContainer.innerHTML = `
        <div class="stat-card">
            <h4>Total des Paquets</h4>
            <p>${summary.total_packets}</p>
        </div>
        <div class="stat-card">
            <h4>Tailles Uniques</h4>
            <p>${summary.unique_sizes}</p>
        </div>
        <div class="stat-card">
            <h4>Taille Moyenne</h4>
            <p>${summary.avg_size.toFixed(2)} bytes</p>
        </div>
    `;
}

function updatePacketSizesChart(packetSizes) {
    if (!packetSizes || packetSizes.length === 0) {
        console.warn('Aucune donnée de taille de paquets disponible');
        return;
    }

    const trace = {
        x: packetSizes,
        type: 'histogram',
        nbinsx: 50,
        name: 'Packet Sizes',
        marker: {
            color: 'rgb(52, 152, 219)',
            line: {
                color: 'rgb(41, 128, 185)',
                width: 1
            }
        }
    };

    const layout = {
        title: {
            text: 'Distribution des Tailles de Paquets',
            font: {
                size: 16
            }
        },
        xaxis: {
            title: 'Taille (octets)'
        },
        yaxis: {
            title: 'Nombre de paquets'
        },
        bargap: 0.05,
        showlegend: false
    };

    Plotly.newPlot('packetSizesChart', [trace], layout);
}

function updateTCPFlagsChart(tcpFlags) {
    if (!tcpFlags || Object.keys(tcpFlags).length === 0) {
        console.warn('Aucune donnée de flags TCP disponible');
        return;
    }

    const data = [{
        values: Object.values(tcpFlags),
        labels: Object.keys(tcpFlags),
        type: 'pie',
        marker: {
            colors: generateColors(Object.keys(tcpFlags).length)
        }
    }];

    const layout = {
        height: 400,
        showlegend: true,
        title: {
            text: 'Distribution des Flags TCP',
            font: {
                size: 16
            }
        }
    };

    Plotly.newPlot('tcpFlagsChart', data, layout);
}

function generateColors(count) {
    const colors = [];
    for (let i = 0; i < count; i++) {
        const hue = (i * 360 / count) % 360;
        colors.push(`hsl(${hue}, 70%, 50%)`);
    }
    return colors;
}

function updateAttackersList(attackers) {
    const attackersContainer = document.getElementById('attackersList');
    attackersContainer.innerHTML = attackers.map(attacker => `
        <div class="attacker-card">
            <h3>Attaquant: ${attacker.ip_address}</h3>
            <p class="attack-type">${attacker.attack_type}</p>
            <ul class="stats-list">
                <li>
                    <span>Paquets totaux:</span>
                    <span>${attacker.packet_count}</span>
                </li>
                <li>
                    <span>Taille moyenne:</span>
                    <span>${attacker.avg_packet_size.toFixed(2)} bytes</span>
                </li>
                <li>
                    <span>Paquets SYN:</span>
                    <span>${attacker.syn_count}</span>
                </li>
                <li>
                    <span>Ports ciblés:</span>
                    <span>${attacker.unique_ports_targeted}</span>
                </li>
            </ul>
        </div>
    `).join('');
}

// Mise à jour automatique
let currentData = null;
setInterval(async () => {
    if (currentData) {
        try {
            const response = await fetch('/get_analysis');
            const data = await response.json();
            updateDashboard(data);
        } catch (error) {
            console.error('Erreur lors de la mise à jour automatique:', error);
        }
    }
}, 30000);