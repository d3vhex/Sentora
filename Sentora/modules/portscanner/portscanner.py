from modules.db import insert_record, delete_all, fetch_where
import socket
import sys
import re
from datetime import datetime
import struct
import asyncio

timeout = 3.0
target = "127.0.0.1"
TABLE = 'portscan_result'

COMMON_PORTS = {
    1: 'TCPMUX', 5: 'RJE', 7: 'Echo', 9: 'Discard', 11: 'Systat', 13: 'Daytime',
    17: 'QOTD', 18: 'MSP', 19: 'CHARGEN', 20: 'FTP-DATA', 21: 'FTP', 22: 'SSH',
    23: 'Telnet', 25: 'SMTP', 37: 'Time', 42: 'WINS', 43: 'WHOIS', 49: 'TACACS',
    53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP', 70: 'Gopher',
    79: 'Finger', 80: 'HTTP', 81: 'HTTP-Alt', 82: 'Torpark', 83: 'MIT-ML-Dev',
    88: 'Kerberos', 100: 'NIC', 101: 'NIC', 102: 'ISO-TSAP', 104: 'ACR-NEMA',
    105: 'CCSO', 107: 'Rtelnet', 109: 'POP2', 110: 'POP3', 111: 'RPC', 113: 'Ident',
    115: 'SFTP', 117: 'UUCP-Path', 119: 'NNTP', 123: 'NTP', 135: 'MS-RPC',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMP-Trap', 163: 'CMIP', 164: 'CMIP', 174: 'MAILQ',
    177: 'XDMCP', 178: 'NextStep', 179: 'BGP', 194: 'IRC', 199: 'SMUX',
    201: 'AppleTalk', 202: 'AppleTalk', 204: 'AppleTalk', 206: 'AppleTalk',
    209: 'QMTP', 210: 'ANSI-Z39.50', 213: 'IPX', 220: 'IMAP3', 245: 'LINK',
    347: 'Fatserv', 363: 'RSVP-Tunnel', 369: 'Rpc2portmap', 370: 'Codaauth2',
    371: 'Clearcase', 372: 'ListProc', 389: 'LDAP', 427: 'SLP', 434: 'MobileIP',
    443: 'HTTPS', 444: 'SNPP', 445: 'SMB', 464: 'Kerberos-Change', 465: 'SMTPS',
    497: 'Retrospect', 500: 'ISAKMP', 512: 'Rexec', 513: 'Rlogin', 514: 'Syslog',
    515: 'LPD', 517: 'Talk', 518: 'NTalk', 520: 'RIP', 521: 'RIPng', 525: 'Timed',
    530: 'RPC', 531: 'IRC', 532: 'Netnews', 533: 'Netwall', 540: 'UUCP',
    543: 'Klogin', 544: 'Kshell', 546: 'DHCPv6-Client', 547: 'DHCPv6-Server',
    548: 'AFP', 550: 'New-RWho', 554: 'RTSP', 556: 'Remotefs', 560: 'Rmonitor',
    561: 'Monitor', 563: 'NNTPS', 587: 'SMTP-Submission', 591: 'FileMaker',
    593: 'MS-RPC-HTTP', 604: 'TUNNEL', 631: 'IPP', 636: 'LDAPS', 639: 'MSDP',
    646: 'LDP', 647: 'DHCP-Failover', 648: 'RRP', 652: 'DTCP', 654: 'AODV',
    665: 'Sun-DR', 666: 'Doom', 674: 'ACAP', 691: 'MS-Exchange', 692: 'Hyperwave-ISP',
    694: 'Linux-HA', 695: 'IEEE-MMS-SSL', 698: 'OLSR', 699: 'Access-Network',
    700: 'EPP', 701: 'LMP', 702: 'IRIS-BEEP', 706: 'SILC', 711: 'Cisco-TDP',
    712: 'TBRPF', 720: 'SMQP', 749: 'Kerberos-Adm', 750: 'Rfile', 751: 'Pump',
    752: 'QRH', 753: 'RRH', 754: 'Tell', 760: 'NS', 782: 'Concert',
    783: 'SpamAssassin', 800: 'MDBS-Daemon', 808: 'OMIRR', 829: 'PKIX-3-CA-RA',
    843: 'Flash-Policy', 873: 'Rsync', 888: 'AccessBuilder', 901: 'SAMBA-SWAT',
    902: 'VMware-Auth', 903: 'VMware-Auth-SSL', 911: 'NCA', 953: 'RNDC',
    981: 'SofaWare', 989: 'FTPS-Data', 990: 'FTPS', 991: 'NAS', 992: 'Telnet-SSL',
    993: 'IMAPS', 995: 'POP3S', 999: 'ScalixAdmin', 1000: 'Cadlock',
    1001: 'Webpush', 1010: 'Surf', 1023: 'Reserved', 1024: 'Reserved',
    1025: 'MS-RPC', 1026: 'MS-RPC', 1027: 'MS-RPC', 1028: 'MS-RPC', 1029: 'MS-RPC',
    1030: 'BBN-IAD', 1080: 'SOCKS', 1099: 'RMI-Registry', 1109: 'KPOP',
    1110: 'NFSd', 1111: 'LM-SSSRV', 1112: 'NFA', 1155: 'NFSD', 1194: 'OpenVPN',
    1234: 'VLC', 1236: 'Bvcontrol', 1241: 'Nessus', 1300: 'H323', 1313: 'BMC-Patrol',
    1334: 'Writesrv', 1352: 'Lotus-Notes', 1433: 'MSSQL', 1434: 'MSSQL-Monitor',
    1494: 'Citrix-ICA', 1500: 'VLSI-LM', 1521: 'Oracle', 1524: 'Ingres',
    1526: 'Oracle-TTC', 1533: 'Virtual-Places', 1534: 'MICROMUSE', 1540: '1C-DB',
    1541: 'FoxBase', 1542: 'SourceForge', 1543: 'SimbaExpress', 1547: 'Laplink',
    1550: 'Gadu-Gadu', 1581: 'MIL-2045', 1582: 'MSIMS', 1583: 'SimbaExpress',
    1589: 'Cisco-VQP', 1604: 'DarkComet', 1645: 'RADIUS', 1646: 'RADIUS-Acct',
    1677: 'GroupWise', 1720: 'H323-Q931', 1723: 'PPTP', 1755: 'MS-Media',
    1801: 'MSMQ', 1812: 'RADIUS', 1813: 'RADIUS-Acct', 1863: 'MSN-Messenger',
    1880: 'Node-RED', 1900: 'UPnP', 1935: 'RTMP', 1972: 'InterSystems',
    2000: 'Cisco-SCCP', 2001: 'DC', 2002: 'Globe', 2003: 'Brutus', 2004: 'Mailbox',
    2005: 'Deslogin', 2010: 'PIP', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
    2086: 'WHM', 2087: 'WHM-SSL', 2100: 'Oracle-XDB', 2121: 'FTP-Proxy',
    2181: 'Zookeeper', 2222: 'SSH-Alt', 2302: 'Halo', 2375: 'Docker',
    2376: 'Docker-TLS', 2379: 'etcd', 2380: 'etcd', 2404: 'IEC-104',
    2483: 'Oracle', 2484: 'Oracle', 2566: 'Vsphere-Client', 2598: 'Citrix',
    2638: 'Sybase', 2947: 'GPS-Daemon', 2967: 'SSC-Agent', 3000: 'Grafana',
    3001: 'Nessus', 3050: 'Interbase', 3074: 'Xbox-Live', 3128: 'Squid-Proxy',
    3200: 'SAP', 3260: 'iSCSI', 3268: 'MS-AD-GC', 3269: 'MS-AD-GC-SSL',
    3283: 'Apple-Remote', 3306: 'MySQL', 3307: 'MySQL-Alt', 3310: 'ClamAV',
    3333: 'DEC-Notes', 3389: 'RDP', 3396: 'Novell', 3478: 'STUN', 3490: 'SAP',
    3493: 'NetSpeech', 3544: 'Teredo', 3632: 'DistCC', 3689: 'iTunes',
    3690: 'SVN', 3724: 'WOW', 3784: 'Ventrilo', 3785: 'Ventrilo', 3799: 'RADIUS',
    3872: 'Oracle-RPC', 4000: 'ICQ', 4001: 'Cisco-ANI', 4045: 'NFS-Lock',
    4200: 'Angular-Dev', 4242: 'Orthanc', 4243: 'Docker', 4303: 'SAP',
    4369: 'Erlang', 4444: 'Metasploit', 4500: 'IPSec-NAT', 4567: 'Sinatra',
    4569: 'IAX2', 4711: 'eMule', 4713: 'PulseAudio', 4730: 'Gearman',
    4786: 'Cisco-Smart-Install', 4800: 'Noxa', 4840: 'OPC-UA', 4899: 'Radmin',
    4949: 'Munin', 5000: 'Flask', 5001: 'Slingbox', 5003: 'FileMaker',
    5004: 'RTP', 5005: 'RTP', 5009: 'Airport-Admin', 5038: 'Asterisk',
    5040: 'Proxy', 5050: 'Yahoo-Messenger', 5060: 'SIP', 5061: 'SIP-TLS',
    5084: 'APNs', 5085: 'APNs', 5090: 'Telnet-Alt', 5093: 'SafeNet',
    5150: 'Ascend', 5190: 'AIM', 5222: 'XMPP', 5223: 'XMPP-SSL', 5269: 'XMPP-Server',
    5280: 'XMPP-HTTP', 5298: 'Presence', 5353: 'mDNS', 5357: 'WSDAPI',
    5400: 'Excerpt-Search', 5432: 'PostgreSQL', 5500: 'VNC', 5555: 'Freeciv',
    5556: 'Freeciv', 5601: 'Kibana', 5631: 'PCAnywhere', 5632: 'PCAnywhere',
    5666: 'Nagios-NRPE', 5672: 'RabbitMQ', 5673: 'JMS', 5800: 'VNC-HTTP',
    5801: 'VNC-HTTP', 5900: 'VNC', 5901: 'VNC', 5938: 'TeamViewer',
    5984: 'CouchDB', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 6000: 'X11',
    6001: 'X11', 6002: 'X11', 6003: 'X11', 6004: 'X11', 6005: 'X11',
    6066: 'EWCTSP', 6080: 'VNC-HTTP', 6081: 'VNC-HTTP', 6100: 'SynchroNet',
    6112: 'Battle-NET', 6123: 'Backup-Express', 6129: 'DameWare',
    6257: 'WinMX', 6346: 'Gnutella', 6347: 'Gnutella', 6379: 'Redis',
    6443: 'Kubernetes-API', 6514: 'Syslog-TLS', 6543: 'Mythtv', 6566: 'SANE',
    6588: 'AnalogX', 6600: 'Music-Player', 6666: 'IRC', 6667: 'IRC',
    6668: 'IRC', 6669: 'IRC', 6679: 'Osorno', 6697: 'IRC-SSL', 6699: 'Napster',
    6881: 'BitTorrent', 6969: 'BitTorrent', 7000: 'AFS', 7001: 'AFS',
    7002: 'AFS', 7070: 'RealServer', 7171: 'Tibia', 7306: 'RTSP-Alt',
    7401: 'RTPS', 7474: 'Neo4j', 7777: 'Terraria', 7878: 'Radarr',
    7890: 'PeerCast', 8000: 'Django', 8008: 'HTTP-Alt', 8009: 'AJP13',
    8010: 'XMPP', 8020: 'Hadoop', 8021: 'FTP-Proxy', 8022: 'PicketLink',
    8030: 'Hadoop', 8031: 'Hadoop', 8032: 'Hadoop', 8042: 'Hadoop',
    8060: 'Roku', 8069: 'OpenERP', 8080: 'HTTP-Proxy', 8081: 'HTTP-Proxy-Alt',
    8086: 'InfluxDB', 8087: 'SPP', 8088: 'HTTP-Alt', 8089: 'Splunk',
    8090: 'Confluence', 8091: 'CouchBase', 8092: 'CouchBase', 8118: 'Privoxy',
    8123: 'Polipo', 8139: 'Puppet', 8140: 'Puppet', 8161: 'ActiveMQ',
    8180: 'HTTP-Alt', 8200: 'GoCD', 8222: 'VMware', 8243: 'HTTPS-Alt',
    8280: 'HTTP-Alt', 8291: 'RouterOS', 8333: 'Bitcoin', 8383: 'Podman',
    8384: 'Syncthing', 8400: 'Commvault', 8443: 'HTTPS-Alt', 8500: 'Consul',
    8530: 'WSUS', 8531: 'WSUS', 8554: 'RTSP', 8649: 'Ganglia', 8686: 'JMX',
    8728: 'MikroTik-API', 8765: 'Ultrasurf', 8800: 'SunWebAdmin',
    8834: 'Nessus', 8880: 'HTTP-Alt', 8883: 'MQTT-SSL', 8888: 'Jupyter',
    8889: 'CDDB', 9000: 'SonarQube', 9001: 'Supervisor', 9002: 'PHP-FPM',
    9009: 'Pichat', 9042: 'Cassandra', 9043: 'WebSphere', 9050: 'Tor-SOCKS',
    9051: 'Tor-Control', 9060: 'WebSphere', 9080: 'HTTP-Alt', 9081: 'HTTP-Alt',
    9090: 'Prometheus', 9091: 'Pushgateway', 9092: 'Kafka', 9093: 'Alertmanager',
    9100: 'Node-Exporter', 9151: 'Tor-Control', 9191: 'Sierra-Wireless',
    9200: 'Elasticsearch', 9201: 'Elasticsearch', 9300: 'Elasticsearch',
    9418: 'Git', 9443: 'WebSphere', 9595: 'Pktstat', 9800: 'WebDAV',
    9869: 'Hadoop', 9997: 'Splunk', 9999: 'Urchin', 10000: 'Webmin',
    10001: 'SCP-Config', 10002: 'DocumentumContent', 10003: 'DocumentumContent',
    10004: 'EMC-Documentum', 10005: 'Documentum', 10006: 'Documentum',
    10007: 'MVS-Capacity', 10008: 'Octopus', 10009: 'Swat', 10010: 'EMC-RPA',
    10050: 'Zabbix-Agent', 10051: 'Zabbix-Server', 10080: 'Amanda',
    10082: 'Amanda', 10083: 'Amanda', 10162: 'SNMP-Trap', 10200: 'FRISK-FP',
    10250: 'Kubelet', 10255: 'Kubelet-Readonly', 10443: 'HTTPS-Alt',
    10554: 'RTSP-Alt', 10616: 'MercuryBoard', 10628: 'MercuryBoard',
    11099: 'RMI-Registry', 11111: 'RMI', 11211: 'Memcached', 11214: 'Memcached',
    11215: 'Memcached', 11234: 'Hotline', 11235: 'Hotline', 11371: 'PGP-HKP',
    11965: 'eLiteboard', 12000: 'CPanel', 12174: 'CPanel', 12201: 'Graylog',
    12345: 'NetBus', 13306: 'MySQL-Alt', 13701: 'NetBackup', 13720: 'NetBackup',
    13721: 'NetBackup', 13724: 'Veritas-VBR', 13782: 'NetBackup',
    13783: 'Veritas-NBU', 14000: 'SSU', 14147: 'Veritas-PBX', 14265: 'Veritas-VCS',
    15000: 'Hydap', 15002: 'Onep-TLS', 16000: 'Sendmail', 16080: 'Mac-OSX-Server',
    16384: 'cPanel', 16385: 'cPanel', 17185: 'Wavemaker', 17500: 'Dropbox',
    18080: 'HTTP-Alt', 18081: 'HTTP-Alt', 18091: 'CouchBase-REST',
    18092: 'CouchBase-Web', 18100: 'Sybase', 18200: 'Sybase', 19132: 'Minecraft-BE',
    19150: 'Gkrellm', 19226: 'AdminProv', 19294: 'Google-Play',
    19812: '4D', 20000: 'DNP', 20547: 'Cyrus-Sieve', 20720: 'Symantec-EPM',
    21025: 'SMTP-Alt', 21379: 'Redis-Alt', 22222: 'SSH-Alt', 22273: 'WMI',
    23399: 'Skype', 23554: 'Apple-Remote-Events', 24444: 'NetBeans',
    24800: 'Synergy', 25000: 'ICAD-EL', 25565: 'Minecraft', 25672: 'RabbitMQ-Dist',
    26000: 'Quake', 26257: 'CockroachDB', 27000: 'FlexNet-Publisher',
    27001: 'FlexNet-Publisher', 27002: 'FlexNet-Publisher', 27015: 'Source-Engine',
    27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB', 27374: 'SubSeven',
    27500: 'QuakeWorld', 27888: 'Kaillera', 27960: 'Quake3', 28015: 'RethinkDB',
    28017: 'MongoDB', 28960: 'Call-of-Duty', 29900: 'Nintendo-WFC',
    30000: 'Ethereum', 30120: 'FiveM', 31337: 'Back-Orifice', 31416: 'BOINC',
    31457: 'TetriNET', 32137: 'Immunet', 32400: 'Plex', 32764: 'SerComm',
    32887: 'ATS', 33848: 'Jenkins', 37777: 'Dahua-Camera', 38292: 'Landesk',
    40000: 'SafetyNET', 41121: 'Tentacle', 41794: 'Crestron', 43110: 'ZeroNet',
    44818: 'EtherNet-IP', 47001: 'WinRM', 47808: 'BACnet', 48556: 'BMC-Patrol',
    49152: 'Private', 49153: 'Private', 50000: 'SAP', 50030: 'Hadoop-TaskTracker',
    50060: 'Hadoop-TaskTracker', 50070: 'Hadoop-NameNode', 50075: 'Hadoop-DataNode',
    50090: 'Hadoop-SecondaryNameNode', 50100: 'Yahoo-Webcam', 51106: 'Deluge',
    55553: 'Metasploit', 55554: 'Metasploit', 60000: 'Mosh', 60001: 'TeamSpeak',
    61613: 'STOMP', 61616: 'ActiveMQ-OpenWire', 64738: 'Mumble'
}

BANNER_PATTERNS = [
    (r'(?i)nginx[/\s]*([\d.]+)', 'NGINX', 1),
    (r'(?i)apache[/\s]*([\d.]+)', 'Apache', 1),
    (r'(?i)microsoft-iis[/\s]*([\d.]+)', 'IIS', 1),
    (r'(?i)lighttpd[/\s]*([\d.]+)', 'Lighttpd', 1),
    (r'(?i)caddy[/\s]*([\d.]+)', 'Caddy', 1),
    (r'(?i)litespeed[/\s]*([\d.]+)', 'LiteSpeed', 1),
    (r'(?i)haproxy[/\s]*([\d.]+)', 'HAProxy', 1),
    (r'(?i)squid[/\s]*([\d.]+)', 'Squid', 1),
    (r'(?i)varnish[/\s]*([\d.]+)', 'Varnish', 1),
    (r'(?i)tomcat[/\s]*([\d.]+)', 'Tomcat', 1),
    (r'(?i)jetty[/\s]*([\d.]+)', 'Jetty', 1),
    (r'(?i)undertow[/\s]*([\d.]+)', 'Undertow', 1),
    (r'(?i)gunicorn[/\s]*([\d.]+)', 'Gunicorn', 1),
    (r'(?i)uvicorn[/\s]*([\d.]+)', 'Uvicorn', 1),
    (r'(?i)puma[/\s]*([\d.]+)', 'Puma', 1),
    (r'(?i)passenger[/\s]*([\d.]+)', 'Passenger', 1),
    (r'(?i)cherokee[/\s]*([\d.]+)', 'Cherokee', 1),
    (r'(?i)mongrel[/\s]*([\d.]+)', 'Mongrel', 1),
    
    (r'(?i)^ssh-([\d.]+)', 'SSH', 1),
    (r'(?i)openssh[_\s]*([\d.p]+)', 'OpenSSH', 1),
    (r'(?i)dropbear[_\s]*([\d.]+)', 'Dropbear-SSH', 1),
    (r'(?i)^http/([\d.]+)', 'HTTP', 1),
    (r'(?i)^rtsp/([\d.]+)', 'RTSP', 1),
    (r'(?i)^ftp.*?ready', 'FTP', 0),
    (r'(?i)^ftp.*?([\d.]+)', 'FTP', 1),
    (r'(?i)proftpd.*?([\d.]+)', 'ProFTPD', 1),
    (r'(?i)pure-ftpd.*?([\d.]+)', 'Pure-FTPd', 1),
    (r'(?i)vsftpd.*?([\d.]+)', 'vsFTPd', 1),
    (r'(?i)filezilla.*?([\d.]+)', 'FileZilla', 1),
    
    (r'(?i)220.*?esmtp', 'SMTP', 0),
    (r'(?i)220.*?smtp', 'SMTP', 0),
    (r'(?i)postfix.*?([\d.]+)', 'Postfix', 1),
    (r'(?i)sendmail.*?([\d.]+)', 'Sendmail', 1),
    (r'(?i)exim.*?([\d.]+)', 'Exim', 1),
    (r'(?i)microsoft\s+exchange', 'Exchange', 0),
    (r'(?i)\+ok.*?pop3', 'POP3', 0),
    (r'(?i)dovecot.*?([\d.]+)', 'Dovecot', 1),
    (r'(?i)\* ok.*?imap', 'IMAP', 0),
    (r'(?i)courier-imap.*?([\d.]+)', 'Courier-IMAP', 1),
    (r'(?i)cyrus.*?imap.*?([\d.]+)', 'Cyrus-IMAP', 1),
    
    (r'(?i)mysql.*?([\d.]+)', 'MySQL', 1),
    (r'(?i)mariadb.*?([\d.]+)', 'MariaDB', 1),
    (r'(?i)percona.*?([\d.]+)', 'Percona', 1),
    (r'(?i)postgresql.*?([\d.]+)', 'PostgreSQL', 1),
    (r'(?i)\$redis', 'Redis', 0),
    (r'(?i)redis.*?([\d.]+)', 'Redis', 1),
    (r'(?i)mongodb.*?([\d.]+)', 'MongoDB', 1),
    (r'(?i)elastic[search]*.*?([\d.]+)', 'Elasticsearch', 1),
    (r'(?i)memcached.*?([\d.]+)', 'Memcached', 1),
    (r'(?i)cassandra.*?([\d.]+)', 'Cassandra', 1),
    (r'(?i)couchdb.*?([\d.]+)', 'CouchDB', 1),
    (r'(?i)rethinkdb.*?([\d.]+)', 'RethinkDB', 1),
    (r'(?i)influxdb.*?([\d.]+)', 'InfluxDB', 1),
    (r'(?i)neo4j.*?([\d.]+)', 'Neo4j', 1),
    (r'(?i)orientdb.*?([\d.]+)', 'OrientDB', 1),
    (r'(?i)arangodb.*?([\d.]+)', 'ArangoDB', 1),
    (r'(?i)microsoft\s+sql\s+server.*?([\d.]+)', 'MSSQL', 1),
    (r'(?i)oracle.*?([\d.]+)', 'Oracle', 1),
    (r'(?i)sybase.*?([\d.]+)', 'Sybase', 1),
    (r'(?i)db2.*?([\d.]+)', 'IBM-DB2', 1),
    
    (r'(?i)rabbitmq.*?([\d.]+)', 'RabbitMQ', 1),
    (r'(?i)kafka.*?([\d.]+)', 'Kafka', 1),
    (r'(?i)activemq.*?([\d.]+)', 'ActiveMQ', 1),
    (r'(?i)zeromq.*?([\d.]+)', 'ZeroMQ', 1),
    (r'(?i)nats.*?([\d.]+)', 'NATS', 1),
    
    (r'(?i)grafana.*?([\d.]+)', 'Grafana', 1),
    (r'(?i)prometheus.*?([\d.]+)', 'Prometheus', 1),
    (r'(?i)kibana.*?([\d.]+)', 'Kibana', 1),
    (r'(?i)graylog.*?([\d.]+)', 'Graylog', 1),
    (r'(?i)splunk.*?([\d.]+)', 'Splunk', 1),
    (r'(?i)nagios.*?([\d.]+)', 'Nagios', 1),
    (r'(?i)zabbix.*?([\d.]+)', 'Zabbix', 1),
    (r'(?i)icinga.*?([\d.]+)', 'Icinga', 1),
    
    (r'(?i)git.*?([\d.]+)', 'Git', 1),
    (r'(?i)gitlab.*?([\d.]+)', 'GitLab', 1),
    (r'(?i)github.*?([\d.]+)', 'GitHub', 1),
    (r'(?i)gitea.*?([\d.]+)', 'Gitea', 1),
    (r'(?i)bitbucket.*?([\d.]+)', 'Bitbucket', 1),
    (r'(?i)svn.*?([\d.]+)', 'SVN', 1),
    
    (r'(?i)vnc.*?rfb\s*([\d.]+)', 'VNC', 1),
    (r'(?i)realvnc.*?([\d.]+)', 'RealVNC', 1),
    (r'(?i)tightvnc.*?([\d.]+)', 'TightVNC', 1),
    (r'(?i)ultravnc.*?([\d.]+)', 'UltraVNC', 1),
    (r'(?i)^rdp', 'RDP', 0),
    (r'(?i)teamviewer.*?([\d.]+)', 'TeamViewer', 1),
    (r'(?i)anydesk.*?([\d.]+)', 'AnyDesk', 1),
    
    (r'(?i)docker.*?([\d.]+)', 'Docker', 1),
    (r'(?i)kubernetes.*?([\d.]+)', 'Kubernetes', 1),
    (r'(?i)k3s.*?([\d.]+)', 'K3s', 1),
    (r'(?i)nomad.*?([\d.]+)', 'Nomad', 1),
    (r'(?i)mesos.*?([\d.]+)', 'Mesos', 1),
    
    (r'(?i)wordpress.*?([\d.]+)', 'WordPress', 1),
    (r'(?i)drupal.*?([\d.]+)', 'Drupal', 1),
    (r'(?i)joomla.*?([\d.]+)', 'Joomla', 1),
    (r'(?i)magento.*?([\d.]+)', 'Magento', 1),
    (r'(?i)prestashop.*?([\d.]+)', 'PrestaShop', 1),
    (r'(?i)django.*?([\d.]+)', 'Django', 1),
    (r'(?i)flask.*?([\d.]+)', 'Flask', 1),
    (r'(?i)laravel.*?([\d.]+)', 'Laravel', 1),
    (r'(?i)symfony.*?([\d.]+)', 'Symfony', 1),
    (r'(?i)express.*?([\d.]+)', 'Express', 1),
    (r'(?i)node.*?js.*?([\d.]+)', 'Node.js', 1),
    (r'(?i)ruby.*?rails.*?([\d.]+)', 'Ruby-on-Rails', 1),
    (r'(?i)asp\.net.*?([\d.]+)', 'ASP.NET', 1),
    
    (r'(?i)plex.*?([\d.]+)', 'Plex', 1),
    (r'(?i)jellyfin.*?([\d.]+)', 'Jellyfin', 1),
    (r'(?i)emby.*?([\d.]+)', 'Emby', 1),
    (r'(?i)kodi.*?([\d.]+)', 'Kodi', 1),
    
    (r'(?i)consul.*?([\d.]+)', 'Consul', 1),
    (r'(?i)etcd.*?([\d.]+)', 'etcd', 1),
    (r'(?i)vault.*?([\d.]+)', 'Vault', 1),
    (r'(?i)jenkins.*?([\d.]+)', 'Jenkins', 1),
    (r'(?i)sonarqube.*?([\d.]+)', 'SonarQube', 1),
    (r'(?i)nexus.*?([\d.]+)', 'Nexus', 1),
    (r'(?i)artifactory.*?([\d.]+)', 'Artifactory', 1),
    (r'(?i)ansible.*?([\d.]+)', 'Ansible', 1),
    (r'(?i)puppet.*?([\d.]+)', 'Puppet', 1),
    (r'(?i)chef.*?([\d.]+)', 'Chef', 1),
    (r'(?i)saltstack.*?([\d.]+)', 'SaltStack', 1),
    (r'(?i)terraform.*?([\d.]+)', 'Terraform', 1),
    (r'(?i)metasploit.*?([\d.]+)', 'Metasploit', 1),
    (r'(?i)nmap.*?([\d.]+)', 'Nmap', 1),
    (r'(?i)wireshark.*?([\d.]+)', 'Wireshark', 1),
    (r'(?i)snort.*?([\d.]+)', 'Snort', 1),
    (r'(?i)suricata.*?([\d.]+)', 'Suricata', 1),
    (r'(?i)openvpn.*?([\d.]+)', 'OpenVPN', 1),
    (r'(?i)wireguard.*?([\d.]+)', 'WireGuard', 1),
    (r'(?i)ipsec.*?([\d.]+)', 'IPSec', 1),
    (r'(?i)bind.*?([\d.]+)', 'BIND', 1),
    (r'(?i)dnsmasq.*?([\d.]+)', 'Dnsmasq', 1),
    (r'(?i)samba.*?([\d.]+)', 'Samba', 1),
    (r'(?i)nfs.*?([\d.]+)', 'NFS', 1),
]

SERVICE_PROBES = {
    'HTTP': [
        b'GET / HTTP/1.0\r\n\r\n',
        b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',
        b'OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    ],
    'HTTPS': [
        b'GET / HTTP/1.0\r\n\r\n',
    ],
    'SMTP': [
        b'EHLO scanner.local\r\n',
        b'HELO scanner\r\n'
    ],
    'FTP': [
        b'USER anonymous\r\n',
        b'HELP\r\n',
        b'FEAT\r\n'
    ],
    'POP3': [
        b'USER test\r\n',
        b'CAPA\r\n'
    ],
    'IMAP': [
        b'A001 CAPABILITY\r\n',
        b'A001 NOOP\r\n'
    ],
    'SSH': [
        b'\r\n',
        b'SSH-2.0-Scanner\r\n'
    ],
    'Telnet': [
        b'\r\n',
        b'\xff\xfb\x01\xff\xfb\x03\xff\xfc\x1f'
    ],
    'MySQL': [
        b'\r\n',
        b'\x00\x00\x00\x0a'
    ],
    'PostgreSQL': [
        b'\x00\x00\x00\x08\x04\xd2\x16/',
    ],
    'Redis': [
        b'INFO\r\n',
        b'PING\r\n',
        b'*1\r\n$4\r\nINFO\r\n'
    ],
    'MongoDB': [
        b'\x3a\x00\x00\x00\x02\x00\x00\x00',
    ],
    'MSSQL': [
        b'\x12\x01\x00\x34\x00\x00\x00\x00',
    ],
    'VNC': [
        b'RFB 003.008\n',
    ],
    'SIP': [
        b'OPTIONS sip:scanner@localhost SIP/2.0\r\n\r\n',
    ],
    'RTSP': [
        b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n',
    ],
    'DNS': [
        b'\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    ],
    'SNMP': [
        b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63',
    ],
    'LDAP': [
        b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00',
    ],
    'RDP': [
        b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00',
    ],
    'SMB': [
        b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00',
    ],
}

def normalize(value):
    return value.replace("'", "''") if isinstance(value, str) else value

def is_duplicate(port, protocol, service, product, version):
    protocol = normalize(protocol)
    service = normalize(service)
    product = normalize(product)
    version = normalize(version)

    condition = (
        f"port = {port} AND "
        f"protocol = '{protocol}' AND "
        f"service = '{service}' AND "
        f"product = '{product}' AND "
        f"version = '{version}'"
    )
    return bool(fetch_where(TABLE, condition))


async def smart_recv(reader, size=8192, max_attempts=5):
    data_parts = []
    attempts = 0
    
    while attempts < max_attempts:
        try:
            import asyncio
            chunk = await asyncio.wait_for(reader.read(size), timeout=1.0)
            if chunk:
                data_parts.append(chunk)
                attempts = 0
            else:
                break
        except asyncio.TimeoutError:
            attempts += 1
            if data_parts:
                break
        except Exception:
            break
    
    return b''.join(data_parts)

async def grab_banner(target, port, timeout=3.0, probes=None):
    all_banners = []
    if probes is None:
        probes = [b'\r\n\r\n', b'']
    
    import asyncio
    for probe in probes:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
            try:
                initial_banner = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                if initial_banner:
                    all_banners.append(initial_banner)
            except asyncio.TimeoutError:
                pass
            
            if probe:
                writer.write(probe)
                await writer.drain()
                response = await smart_recv(reader)
                if response:
                    all_banners.append(response)
                    
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
        except Exception:
            continue
    
    if all_banners:
        return b'\n'.join(all_banners).decode(errors='ignore').strip()
    return ''

def detect_service_from_banner(banner, port):
    if not banner: return None, None, None
    import re
    for pattern, service, version_group in BANNER_PATTERNS:
        match = re.search(pattern, banner)
        if match:
            version = "Unknown"
            if version_group and len(match.groups()) >= version_group:
                version = match.group(version_group)
            product = service
            product_patterns = [
                rf'({service}[/\s-]*[\w.]*)',
                rf'([A-Za-z0-9\-_.]+)[/\s]*{re.escape(version)}' if version != "Unknown" else None,
                rf'([A-Za-z0-9\-_.]+)[/\s]+[\d.]+'
            ]
            for pp in product_patterns:
                if pp:
                    pm = re.search(pp, banner, re.IGNORECASE)
                    if pm:
                        product = pm.group(1).strip()
                        break
            return service, product, version
    
    banner_lower = banner.lower()
    for service_name in ['nginx', 'apache', 'mysql', 'postgresql', 'redis', 'mongodb', 
                         'elasticsearch', 'docker', 'ssh', 'ftp', 'smtp', 'pop3', 'imap',
                         'http', 'https', 'vnc', 'rdp', 'ldap', 'dns', 'dhcp', 'nfs',
                         'smb', 'telnet', 'snmp', 'sip', 'rtsp', 'ntp', 'kerberos']:
        if service_name in banner_lower:
            version_match = re.search(rf'{service_name}[/\s-]*([\d.]+)', banner, re.IGNORECASE)
            version = version_match.group(1) if version_match else "Unknown"
            return service_name.upper(), service_name.capitalize(), version
    return None, None, None

async def detect_service(target, port, timeout):
    import socket, re
    base_service = COMMON_PORTS.get(port, None)
    probes = [b'\r\n\r\n', b'']
    if base_service:
        service_key = base_service.split('-')[0]
        if service_key in SERVICE_PROBES:
            probes = SERVICE_PROBES[service_key] + probes
        elif base_service in SERVICE_PROBES:
            probes = SERVICE_PROBES[base_service] + probes
    
    if port in [80, 81, 82, 443, 8000, 8008, 8080, 8081, 8088, 8090, 8180, 8280, 8443, 8880, 9000, 9080, 9090]:
        probes = SERVICE_PROBES.get('HTTP', []) + probes
    
    banner = await grab_banner(target, port, timeout, probes)
    
    if banner:
        service, product, version = detect_service_from_banner(banner, port)
        if service:
            if base_service and base_service != service:
                if base_service.lower() in service.lower() or service.lower() in base_service.lower():
                    return base_service, product, version, banner
            return service, product, version, banner
            
    if base_service:
        version = "Unknown"
        product = base_service
        if banner:
            version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)?(?:\.[\d]+)?)', banner)
            if version_match: version = version_match.group(1)
            product_match = re.search(r'([A-Za-z0-9\-_.]+)\s*[/\s]*([\d.]+)', banner)
            if product_match:
                product = product_match.group(1)
                version = product_match.group(2)
        return base_service, product, version, banner
        
    try:
        service = socket.getservbyport(port, 'tcp')
        product = service
        version = "Unknown"
        if banner:
            version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)?)', banner)
            if version_match: version = version_match.group(1)
            first_word = banner.split()[0] if banner.split() else service
            if first_word and len(first_word) > 2: product = first_word
        return service, product, version, banner
    except OSError:
        pass
        
    if banner:
        words = banner.split()
        if words:
            product = words[0][:50]
            version_match = re.search(r'([\d]+\.[\d]+(?:\.[\d]+)?)', banner)
            version = version_match.group(1) if version_match else "Unknown"
            return f"TCP-{port}", product, version, banner
            
    return f'TCP-{port}', f'Unknown-{port}', 'Unknown', banner

async def scan_single_port(target, port, timeout, semaphore, scanned_counter, result_queue):
    import asyncio
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            
            service, product, version, banner = await detect_service(target, port, timeout)
            await result_queue.put((port, 'tcp', service, product, version, banner))
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
        finally:
            scanned_counter['count'] += 1
            if scanned_counter['count'] % 5000 == 0:
                print(f"[*] Progress: {scanned_counter['count']}/65535 ports scanned...")

async def scan_ports(target, timeout):
    import asyncio
    import sys
    print(f"[*] Scanning all ports (1-65535) on {target} (AsyncIO)...")
    max_concurrent = 400 if sys.platform == 'win32' else 1500
    semaphore = asyncio.Semaphore(max_concurrent)
    result_queue = asyncio.Queue()
    scanned_counter = {'count': 0}

    tasks = [asyncio.create_task(scan_single_port(target, port, timeout, semaphore, scanned_counter, result_queue)) for port in range(1, 65536)]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    
    results = []
    while not result_queue.empty():
        res = await result_queue.get()
        port, protocol, service, product, version, banner = res
        results.append((port, protocol, service, product, version))
        
        banner_preview = banner[:80] + '...' if banner and len(banner) > 80 else banner
        print(f"[+] {port:5d}/tcp - {service:20s} | {product:20s} | v{version}")
        if banner_preview:
            print(f"    └─ Banner: {banner_preview}")
            
    return results

async def main_async():
    from datetime import datetime
    import sys
    print(f"{'='*70}")
    print(f"  Advanced Port Scanner - AsyncI/O Stealth")
    print(f"{'='*70}")
    print(f"[*] Target: {target}")
    print(f"[*] Timeout: {timeout}s")
    print(f"[*] Port Range: 1-65535")
    print(f"{'='*70}\n")
    
    start_time = datetime.utcnow()
    try:
        total_found = 0
        total_saved = 0
        results = await scan_ports(target, timeout)
        
        for port, protocol, service, product, version in results:
            total_found += 1
            if not is_duplicate(port, protocol, service, product, version):
                insert_record(
                    TABLE,
                    {
                        'port': port,
                        'protocol': protocol,
                        'service': service,
                        'product': product,
                        'version': version,
                        'scanned_at': datetime.utcnow(),
                    },
                )
                total_saved += 1
                
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n{'='*70}")
        print(f"[✓] Scan Complete!")
        print(f"{'='*70}")
        print(f"  Duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")
        print(f"  Ports Found: {total_found}")
        print(f"  New Records Saved: {total_saved}")
        print(f"  Duplicates Skipped: {total_found - total_saved}")
        print(f"{'='*70}\n")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)

def main():
    import sys
    import asyncio
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
