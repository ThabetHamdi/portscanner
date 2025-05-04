from flask import Flask, render_template, request
from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr, sr1, RandShort
import ipaddress

app = Flask(__name__)
#list of usual ports to scan
# 21: FTP, 22: SSH, 23: Telnet, 25: SMTP, 53: DNS, 67: DHCP, 68: DHCP, 80: HTTP, 110: POP3, 123: NTP, 135: RPC, 139: NetBIOS, 143: IMAP, 161: SNMP, 162: SNMP, 443: HTTPS, 445: SMB, 3389: RDP, 8080: HTTP, 8443: HTTPS

portlist = [21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 139, 143,
                161, 162, 443, 445, 3389, 8080, 8443]

def portscan(host):
    results = []
    try:
        packets, _ = sr(IP(dst=host)/TCP(sport=RandShort(), dport=portlist, flags="S"), timeout=2, verbose=0)
        for sent, recv in packets:
            if recv.haslayer(TCP):
                flag = recv[TCP].flags
                if flag == "SA":
                    results.append(f"Port {sent[TCP].dport} is open")
                elif flag == "RA":
                    results.append(f"Port {sent[TCP].dport} is closed")
                    
    except Exception as e:
        results.append(f"something is wrong  {e}")
    return results

def dnscanner(host):
    output = []
    try:
        packet = IP(dst=host)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        reply = sr1(packet, timeout=2, verbose=0)
        if reply and reply.haslayer(DNS) and reply[DNS].ancount > 0:
            output.append(f"DNS server at {host} is responding")
            for i in range(reply[DNS].ancount):
                rr = reply[DNS].an[i]
                if rr.type == 1:
                    output.append(f"{rr.rrname.decode()} -> {rr.rdata}")
        else:
            output.append(f"No DNS anwser from  {host}")
    except Exception as e:
        output.append(f"DNS scan failed {e}")
    return output

@app.route("/", methods=["GET", "POST"])
def index():
    results = {"syn": [], "dns": []}
    error = None
    if request.method == "POST":
        ip = request.form.get("ip")
        try:
            ip_obj = ipaddress.ip_address(ip)
            # stop scanning if the address is a broadcast or multicast address
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local or ip.endswith(".255"):
                error = "Broadcast and multicast addresses are not possible to scan "
            else:
                results["syn"] = portscan(ip)
                results["dns"] = dnscanner(ip)
        except ValueError:
            error = "ip address not valid or not in the right format"
    return render_template("index.html", results=results, error=error)

if __name__ == "__main__":
    app.run(debug=True)
