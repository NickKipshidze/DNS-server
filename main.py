import argparse, datetime, sys, time, threading, traceback, socketserver, struct, dnslib
from dnslib import QTYPE

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + "." + self)

ZONES = [
    {
        "name": "example.com.",
        "ip": "192.168.0.100",
        "ttl": 60 * 5,
    }
]

for zone in ZONES:
    zone["name"] = DomainName(zone["name"])
    
    zone["soa_record"] = dnslib.SOA(
        mname=zone["name"].ns1,
        rname=zone["name"].andrei,
        times=(
            201307231,
            60 * 60 * 1,
            60 * 60 * 3,
            60 * 60 * 24,
            60 * 60 * 1,
        )
    )
    
    zone["ns_records"] = [
        dnslib.NS(zone["name"].ns1),
        dnslib.NS(zone["name"].ns2)
    ]
        
    zone["records"] = {
        zone["name"]: [dnslib.A(zone["ip"]), dnslib.AAAA((0,) * 16), dnslib.MX(zone["name"].mail), zone["soa_record"]] + zone["ns_records"],
        zone["name"].ns1: [dnslib.A(zone["ip"])],
        zone["name"].ns2: [dnslib.A(zone["ip"])],
        zone["name"].mail: [dnslib.A(zone["ip"])],
        zone["name"].andrei: [dnslib.CNAME(zone["name"])],
    }

def dns_response(data):
    request = dnslib.DNSRecord.parse(data)

    print(request)

    reply = dnslib.DNSRecord(
        dnslib.DNSHeader(
            id=request.header.id,
            qr=1,
            aa=1,
            ra=1
        ),
        q=request.q
    )

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    for zone in ZONES:
        if qn == zone["name"] or qn.endswith("." + zone["name"]):
            for name, rrs in zone["records"].items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ["*", rqt]:
                            reply.add_answer(
                                dnslib.RR(
                                    rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=zone["ttl"], rdata=rdata
                                )
                            )

            for rdata in zone["ns_records"]:
                reply.add_ar(
                    dnslib.RR(
                        rname=zone["name"], rtype=QTYPE.NS, rclass=1, ttl=zone["ttl"], rdata=rdata
                    )
                )

            reply.add_auth(
                dnslib.RR(
                    rname=zone["name"], rtype=QTYPE.SOA, rclass=1, ttl=zone["ttl"], rdata=zone["soa_record"]
                )
            )

    print("---- Reply:\n", reply)

    return reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"\n\n{self.__class__.__name__[:3]} request {now} ({self.client_address[0]} {self.client_address[1]}):")
        try:
            data = self.get_data()
            print(len(data), data)
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack(">H", data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack(">H", len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main():
    parser = argparse.ArgumentParser(description="Start a DNS implemented in Python.")
    parser = argparse.ArgumentParser(description="Start a DNS implemented in Python. Usually DNSs use UDP on port 53.")
    parser.add_argument("--port", default=5053, type=int, help="The port to listen on.")
    parser.add_argument("--tcp", action="store_true", help="Listen to TCP connections.")
    parser.add_argument("--udp", action="store_true", help="Listen to UDP datagrams.")
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers: list[socketserver.ThreadingTCPServer | socketserver.ThreadingUDPServer] = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(("", args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(("", args.port), TCPRequestHandler))

    for server in servers:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        print(f"{server.RequestHandlerClass.__name__[:3]} server loop running in thread: {thread.name}")

    try:
        while True:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()

if __name__ == "__main__":
    main()
