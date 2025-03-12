package nmap

import (
	"fmt"
	"strings"
)

// Protocol type represents network protocol (TCP or UDP)
type Protocol string

const (
	// TCP protocol
	TCP Protocol = "tcp"
	// UDP protocol
	UDP Protocol = "udp"
)

// NamedPort represents a network port with its associated service name and protocol
type NamedPort struct {
	Port     int
	Service  string
	Protocol Protocol
}

// CommonPorts defines standard ports and their associated services
var CommonPorts = []NamedPort{
	// Basic Internet Services
	{20, "FTP-Data", TCP},
	{21, "FTP-Control", TCP},
	{22, "SSH", TCP},
	{23, "Telnet", TCP},
	{25, "SMTP", TCP},
	{43, "WHOIS", TCP},
	{80, "HTTP", TCP},
	{443, "HTTPS", TCP},
	{989, "FTPS-Data", TCP},
	{990, "FTPS-Control", TCP},
	{992, "Telnet-over-TLS", TCP},
	{992, "Telnet-over-TLS", UDP},
	{8080, "HTTP-Proxy", TCP},
	{8443, "HTTPS-Alt", TCP},

	// Email Services
	{109, "POP2", TCP},
	{110, "POP3", TCP},
	{143, "IMAP", TCP},
	{209, "QMTP", TCP},
	{220, "IMAP3", TCP},
	{465, "SMTP-SSL", TCP},
	{587, "SMTP-Submission", TCP},
	{691, "Microsoft-Exchange", TCP},
	{993, "IMAPS", TCP},
	{995, "POP3S", TCP},
	{2525, "SMTP-Alt1", TCP},

	// Name Services & Discovery
	{53, "DNS", TCP},
	{53, "DNS", UDP},
	{67, "DHCP-Server", UDP},
	{68, "DHCP-Client", UDP},
	{137, "NetBIOS-Name", UDP},
	{138, "NetBIOS-Datagram", UDP},
	{139, "NetBIOS-Session", TCP},
	{546, "DHCPv6-Client", UDP},
	{547, "DHCPv6-Server", UDP},
	{647, "DHCP-failover", TCP},
	{847, "DHCP-failover", TCP},
	{853, "DNS-over-TLS", TCP},
	{853, "DNS-over-QUIC", UDP},
	{953, "DNS-RNDC", TCP},

	// Remote Access & Management
	{88, "Kerberos", TCP},
	{464, "Kerberos-Password", TCP},
	{513, "Rlogin", TCP},
	{514, "Cmd/Rsh", TCP},
	{514, "Syslog", UDP},
	{544, "Kerberos-Remote-Shell/Kshell", TCP},
	{749, "Kerberos-Admin", TCP},
	{1494, "Citrix-ICA", TCP},
	{1723, "PPTP", TCP},
	{3389, "RDP", TCP},
	{3389, "RDP", UDP},
	{5500, "VNC-Server", TCP},
	{5800, "VNC-HTTP", TCP},
	{5900, "VNC", TCP},
	{5938, "TeamViewer", TCP},
	{6514, "Syslog", TCP},

	// File Sharing & Transfer
	{69, "TFTP", UDP},
	{115, "SFTP-Legacy", TCP},
	{445, "SMB", TCP},
	{548, "AFP", TCP},
	{873, "Rsync", TCP},
	{2049, "NFS", TCP},
	{2049, "NFS", UDP},
	{8384, "Syncthing-WebUI", TCP},      // Syncthing web interface
	{22000, "Syncthing-Relay", TCP},     // Syncthing file transfer
	{22000, "Syncthing-Relay", UDP},     // Syncthing protocol discovery
	{21027, "Syncthing-Discovery", UDP}, // Syncthing local discovery

	// Directory & Authentication Services
	{88, "Kerberos", UDP},
	{389, "LDAP", TCP},
	{543, "Kerberos-login/Klogin", TCP},
	{636, "LDAPS", TCP},
	{1812, "RADIUS-Auth", UDP},
	{1813, "RADIUS-Accounting", UDP},
	{11371, "OpenPGP-HKP", TCP}, // OpenPGP HTTP Keyserver Protocol

	// Database Services
	{1433, "MS-SQL", TCP},
	{1434, "MS-SQL-Monitor", UDP},
	{1521, "Oracle-DB", TCP},
	{1526, "Oracle-Listener", TCP},
	{3050, "Firebird", TCP},
	{3306, "MySQL", TCP},
	{3307, "MySQL-Alt", TCP},
	{5432, "PostgreSQL", TCP},
	{5984, "CouchDB", TCP},
	{6379, "Redis", TCP},
	{6380, "Redis-Alt", TCP},
	{7000, "Cassandra/PeerVPN", TCP},
	{7473, "Neo4j-HTTP", TCP},
	{8086, "InfluxDB", TCP},
	{9042, "Cassandra-CQL", TCP},
	{9100, "ClickHouse/JetDirect", TCP},
	{9200, "Elasticsearch-HTTP", TCP},
	{9300, "Elasticsearch-Transport", TCP},
	{27017, "MongoDB", TCP},
	{27018, "MongoDB-Shard", TCP},
	{27019, "MongoDB-Config", TCP},
	{28015, "RethinkDB", TCP},

	// Messaging & Communication
	{119, "NNTP", TCP},
	{194, "IRC", TCP},
	{563, "NNTP-TLS", TCP},
	{631, "IPP", TCP},
	{1503, "Windows-Messenger", TCP},
	{1863, "MSNP", TCP},
	{5060, "SIP", TCP},
	{5060, "SIP", UDP},
	{5061, "SIP-TLS", TCP},
	{5222, "XMPP-Client", TCP},
	{5223, "XMPP-Client-SSL", TCP},
	{5269, "XMPP-Server", TCP},
	{6660, "IRC", TCP},
	{6661, "IRC", TCP},
	{6662, "IRC", TCP},
	{6663, "IRC", TCP},
	{6664, "IRC", TCP},
	{6665, "IRC", TCP},
	{6666, "IRC", TCP},
	{6667, "IRC", TCP},
	{6668, "IRC", TCP},
	{6669, "IRC", TCP},
	{6697, "IRC-SSL", TCP},
	{7000, "IRC", TCP},

	// Network Services
	{37, "Time-Protocol", TCP},
	{37, "Time-Protocol", UDP},
	{79, "Finger", TCP},
	{111, "RPC", TCP},
	{111, "RPC", UDP},
	{123, "NTP", UDP},
	{135, "MSRPC", TCP},
	{161, "SNMP", UDP},
	{162, "SNMP-Trap", UDP},
	{179, "BGP", TCP},
	{500, "IKE", UDP},
	{514, "Syslog", UDP},
	{515, "Printer-LPD", TCP},
	{554, "RTSP", TCP},
	{601, "Syslog", TCP},
	{655, "Tinc", TCP},
	{655, "Tinc", UDP},
	{1080, "SOCKS-Proxy", TCP},
	{1194, "OpenVPN", UDP},
	{1701, "L2TP", UDP},
	{1900, "UPnP", UDP},
	{3128, "Squid-Proxy", TCP},
	{4500, "IPsec-NAT", UDP},
	{5353, "mDNS", UDP},
	{11211, "Memcached", TCP},
	{11211, "Memcached", UDP},
	{51820, "WireGuard", UDP},

	// Web Hosting & Control Panels
	{81, "HTTP-Alt1", TCP},
	{82, "HTTP-Alt2", TCP},
	{2082, "cPanel", TCP},
	{2083, "cPanel-SSL", TCP},
	{2086, "WHM", TCP},
	{2087, "WHM-SSL", TCP},
	{2222, "SSH-Alt", TCP},
	{8000, "HTTP-Alt/SAP-WebGUI", TCP},
	{8008, "HTTP-Alt4", TCP},
	{8081, "HTTP-Alt2", TCP},
	{8888, "HTTP-Alt/Jupyter", TCP},
	{9443, "HTTPS-Alt3", TCP},
	{10000, "Webmin", TCP},

	// Development & Source Control
	{3000, "Ruby-Dev/Grafana", TCP},
	{3001, "React-Dev", TCP},
	{3002, "NextJS-Dev", TCP},
	{3003, "Express", TCP},
	{3690, "SVN", TCP},
	{4200, "Angular", TCP},
	{5173, "Vite", TCP},
	{8787, "RStudio", TCP},
	{9418, "Git", TCP},
	{9999, "Web-Alt", TCP},

	// Cloud/DevOps Services
	{2181, "ZooKeeper", TCP},
	{2375, "Docker-API", TCP},
	{2376, "Docker-API-TLS", TCP},
	{2379, "etcd", TCP},
	{4369, "Erlang-EPMD", TCP},
	{5601, "Kibana", TCP},
	{6443, "Kubernetes-API", TCP},
	{7001, "WebLogic", TCP},
	{7002, "WebLogic-SSL", TCP},
	{8200, "HashiCorp-Vault", TCP},
	{8500, "Consul", TCP},
	{8834, "Nessus", TCP},
	{9000, "S3-API/SonarQube", TCP},
	{9090, "Prometheus", TCP},
	{9092, "Kafka", TCP},
	{10250, "Kubernetes-Kubelet", TCP},

	// OpenStack services
	{5000, "OpenStack-Keystone/Flask", TCP}, // OpenStack Identity API
	{8774, "OpenStack-Nova", TCP},           // OpenStack Compute API
	{9292, "OpenStack-Glance", TCP},         // OpenStack Image Service
	{9696, "OpenStack-Neutron", TCP},        // OpenStack Networking
	{8776, "OpenStack-Cinder", TCP},         // OpenStack Block Storage
	{8004, "OpenStack-Heat", TCP},           // OpenStack Orchestration
	{8778, "OpenStack-Placement", TCP},      // OpenStack Placement API
	{6385, "OpenStack-Ironic", TCP},         // OpenStack Bare Metal Service
	{35357, "OpenStack-KeystoneAdmin", TCP}, // OpenStack Identity Admin API

	// Specialized Services
	{1880, "Node-RED", TCP},
	{1883, "MQTT", TCP},
	{3478, "Headscale", UDP},
	{4242, "Nebula", UDP},
	{4444, "Metasploit", TCP},
	{5672, "RabbitMQ", TCP},
	{5986, "WinRM-HTTPS", TCP},
	{6000, "X11", TCP},
	{8123, "Home-Assistant", TCP},
	{8333, "Bitcoin", TCP},
	{8501, "Streamlit", TCP},
	{8545, "Ethereum-RPC", TCP},
	{8843, "UniFi-HTTPS", TCP},
	{8883, "MQTT-TLS", TCP},
	{8983, "Solr", TCP},
	{9001, "Tor-Orport", TCP},
	{9030, "Tor-Dirport", TCP},
	{9035, "Tor-MetricsPort", TCP},
	{9091, "Transmission", TCP},
	{9993, "ZeroTier", UDP},
	{15672, "RabbitMQ-Admin", TCP},
	{41641, "Tailscale/Headscale", UDP},

	// Application & Media Services
	{1935, "RTMP", TCP},
	{5004, "RTP", UDP},
	{5005, "RTCP", UDP},
	{6006, "TensorBoard", TCP},
	{6881, "BitTorrent", TCP},
	{6969, "BitTorrent-Tracker", TCP},
	{7070, "RTSP-Alt", TCP},
	{8005, "Tomcat-Shutdown", TCP},
	{8009, "AJP", TCP},
	{8096, "Jellyfin", TCP},
	{32400, "Plex", TCP},           // Primary Plex web interface and streaming
	{32410, "Plex-Companion", UDP}, // Plex Companion discovery
	{32469, "Plex-DLNA", TCP},      // Plex DLNA streaming

	// Game Servers
	{3074, "Xbox-Live", TCP},
	{3724, "WoW", TCP},
	{6112, "Battle.net", TCP},
	{7171, "Tibia", TCP},
	{7777, "GameServer-Generic", TCP},
	{9987, "TeamSpeak-Voice", UDP},         // TeamSpeak 3 default voice port
	{10011, "TeamSpeak-ServerQuery", TCP},  // TeamSpeak server query port
	{30033, "TeamSpeak-FileTransfer", TCP}, // TeamSpeak file transfer port
	{25565, "Minecraft", TCP},
	{27015, "Steam", TCP},
	{27015, "Steam", UDP},
	{27016, "Source-RCON", TCP},
	{28960, "Call-of-Duty", TCP},

	// IoT/Smart Home
	{5683, "CoAP", UDP},
	{5684, "CoAPS", UDP},

	// Industrial & SCADA
	{102, "SIEMENS-S7", TCP},
	{502, "Modbus", TCP},
	{1911, "Tridium-Fox", TCP},
	{2404, "IEC-60870-5-104", TCP},
	{4000, "Ethernet/IP", TCP},
	{4840, "OPC-UA", TCP},
	{20000, "DNP3", TCP},
	{44818, "Ethernet/IP", TCP},

	// Monitoring & Management
	{5044, "Logstash-Beats", TCP},
	{5666, "NRPE", TCP},
	{9997, "Splunk-Collector", TCP},
	{10050, "Zabbix-Agent", TCP},
	{10051, "Zabbix-Server", TCP},

	// Storage Services
	{860, "iSCSI", TCP},
	{3260, "iSCSI", TCP},
	{3300, "Ceph-Mon", TCP},     // Ceph Monitor (newer versions)
	{6789, "Ceph-Mon-V2", TCP},  // Ceph Monitor (older versions)
	{7480, "Ceph-RGW", TCP},     // Ceph Object Gateway (HTTP)
	{7481, "Ceph-RGW-TLS", TCP}, // Ceph Object Gateway (HTTPS)
	{6800, "Ceph-OSD", TCP},     // Ceph OSD/MDS (start of range)

	// Authentication & Management
	{113, "Ident", TCP},           // User identification protocol
	{5985, "WinRM-HTTP", TCP},     // Windows Remote Management (HTTP)
	{16992, "Intel-AMT", TCP},     // Intel Active Management Technology
	{16993, "Intel-AMT-TLS", TCP}, // Intel AMT over TLS

	// Networking & Devices
	{8291, "MikroTik", TCP},            // MikroTik RouterOS administration
	{9440, "Nutanix-AHV", TCP},         // Nutanix hypervisor management
	{4786, "Cisco-Smart-Install", TCP}, // Cisco Smart Install

	// Common Services
	{177, "XDMCP", UDP},        // X Display Manager Control Protocol
	{1099, "Java-RMI", TCP},    // Java Remote Method Invocation
	{5555, "Android-ADB", TCP}, // Android Debug Bridge
	{5901, "VNC-1", TCP},       // VNC Display :1
	{5902, "VNC-2", TCP},       // VNC Display :2

	// Big Data & Analytics
	{50070, "Hadoop-NameNode", TCP},       // Hadoop NameNode WebUI
	{50075, "Hadoop-DataNode", TCP},       // Hadoop DataNode WebUI
	{8088, "Hadoop-ResourceManager", TCP}, // YARN Resource Manager

	// Registrar/Registries Communication
	{648, "RRP", TCP},
	{700, "EPP", TCP},
  
 	// Enterprise Applications
	{3299, "SAP", TCP},       // SAP services
	{9080, "WebSphere", TCP}, // IBM WebSphere Application Server
}

// portsToString converts a slice of NamedPort to a comma-separated string of port numbers
// with protocol prefixes (t: for TCP, u: for UDP)
func portsToString(ports []NamedPort) string {
	tcpPorts := make([]string, 0)
	udpPorts := make([]string, 0)

	for _, port := range ports {
		if port.Protocol == TCP {
			tcpPorts = append(tcpPorts, fmt.Sprintf("%d", port.Port))
		} else if port.Protocol == UDP {
			udpPorts = append(udpPorts, fmt.Sprintf("%d", port.Port))
		}
	}

	result := ""
	if len(tcpPorts) > 0 {
		result += "T:" + strings.Join(tcpPorts, ",")
	}
	if len(udpPorts) > 0 {
		if result != "" {
			result += ","
		}
		result += "U:" + strings.Join(udpPorts, ",")
	}
	return result
}
