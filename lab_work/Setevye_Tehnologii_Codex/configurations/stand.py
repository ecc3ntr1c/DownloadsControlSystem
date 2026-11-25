"""Изолированная модель учебных стендов. Сетевой трафик в ОС не отправляется."""
import argparse
import heapq
import json
from collections import Counter, deque
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path

MASK24 = "255.255.255.0"


@dataclass(frozen=True)
class PC:
    name: str
    switch: str
    port: str
    vlan: int
    address: IPv4Interface
    gateway: str | None


def pc(name, switch, port, vlan, ip, prefix=24, gateway=None):
    return PC(name, switch, port, vlan, IPv4Interface(f"{ip}/{prefix}"), gateway)


@dataclass(frozen=True)
class Trunk:
    left: str
    left_port: str
    right: str
    right_port: str
    vlans: tuple[int, ...]


def vlan_path(src, dst, vlan, trunks):
    queue = deque([(src, [src])])
    seen = {src}
    while queue:
        switch, path = queue.popleft()
        if switch == dst:
            return path
        for trunk in trunks:
            if vlan not in trunk.vlans:
                continue
            neighbor = None
            if trunk.left == switch:
                neighbor = trunk.right
            elif trunk.right == switch:
                neighbor = trunk.left
            if neighbor is not None and neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, path + [neighbor]))
    return None


def trace_lan(a, b, trunks, router_ports, prefix="Router0"):
    if a.address.network == b.address.network and a.vlan == b.vlan:
        route = vlan_path(a.switch, b.switch, a.vlan, trunks)
        return [a.name, *route, b.name] if route else None

    a_port = router_ports.get(a.vlan)
    b_port = router_ports.get(b.vlan)
    if not a_port or not b_port or a.gateway != a_port[1] or b.gateway != b_port[1]:
        return None

    left = vlan_path(a.switch, a_port[0], a.vlan, trunks)
    right = vlan_path(b_port[0], b.switch, b.vlan, trunks)
    if not left or not right:
        return None
    return [a.name, *left, prefix, *right, b.name]


def ping_table(pcs, trace, pairs):
    rows = []
    for src, dst in pairs:
        path = trace(pcs[src], pcs[dst])
        reply = trace(pcs[dst], pcs[src])
        rows.append({"source": src, "target": dst, "ip": str(pcs[dst].address.ip),
                     "received": 4 if path and reply else 0, "sent": 4,
                     "path": path, "reply": reply})
    return rows


def link_test_rows(pcs, trace):
    return ping_table(pcs, trace, [(a, b) for a in pcs for b in pcs if a != b])


def pc_rows(pcs):
    return [{"pc": p.name, "switch": p.switch, "port": p.port, "vlan": p.vlan,
             "ip": str(p.address.ip), "mask": str(p.address.netmask), "gateway": p.gateway}
            for p in pcs.values()]


def config(out, filename, body):
    full = out / filename
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text("\n".join(body) + "\n", encoding="utf-8")


def ios(out, filename, commands):
    config(out, filename, ["enable", "configure terminal", *commands, "end"])


def access(port, vlan):
    return [f"interface {port}", " switchport mode access", f" switchport access vlan {vlan}", "exit"]


def trunk_ios(port, vlans):
    return [f"interface {port}", " switchport mode trunk",
            " switchport trunk allowed vlan " + ",".join(map(str, vlans)), "exit"]


def interface(port, ip, mask):
    return [f"interface {port}", f" ip address {ip} {mask}", " no shutdown", "exit"]


def lab1(n, out):
    first = f"192.168.{n}"
    second = f"192.168.{n + 1}"
    pcs = {f"PC{i}": pc(f"PC{i}", "Switch0" if i <= 4 else "Switch1",
                         f"Fa0/{i if i <= 4 else i-4}", 1 if i <= 4 else 2,
                         f"{first}.{i}" if i <= 4 else f"{second}.{i-4}",
                         gateway=f"{first if i <= 4 else second}.254")
           for i in range(1, 7)}
    router_ports = {1: ("Switch0", f"{first}.254"), 2: ("Switch1", f"{second}.254")}
    trace = lambda a, b: trace_lan(a, b, (), router_ports)
    tests = ping_table(pcs, trace, [("PC1", "PC3"), ("PC5", "PC6"), ("PC1", "PC5"),
                                   ("PC5", "PC1"), ("PC4", "PC6")])
    assert all(row["received"] == 4 for row in link_test_rows(pcs, trace))
    ios(out, "lab1/Router0.txt", ["hostname Router0",
        *interface("FastEthernet0/0", f"{first}.254", MASK24),
        *interface("FastEthernet0/1", f"{second}.254", MASK24)])
    for sw in ("Switch0", "Switch1"):
        ios(out, f"lab1/{sw}.txt", ["hostname " + sw])
    rows = pc_rows(pcs)
    for row in rows:
        del row["vlan"]
    return {"pcs": rows, "results": tests, "router": [
        ("Fa0/0", f"{first}.254", "Switch0", "Fa0/24"),
        ("Fa0/1", f"{second}.254", "Switch1", "Fa0/24")]}


def lab2(n, out):
    order = [
        ("PC11", "Switch0", 1, 10, 1), ("PC12", "Switch0", 2, 20, 1),
        ("PC13", "Switch0", 3, 20, 2), ("PC14", "Switch0", 4, 1, 1),
        ("PC21", "Switch1", 1, 10, 2), ("PC22", "Switch1", 2, 20, 3),
        ("PC23", "Switch1", 3, 20, 4), ("PC24", "Switch1", 4, 30, 1),
        ("PC25", "Switch1", 5, 30, 2), ("PC31", "Switch2", 1, 10, 3),
        ("PC34", "Switch2", 2, 30, 3), ("PC35", "Switch2", 3, 30, 4),
        ("PC32", "Switch2", 4, 1, 2),
    ]
    prefixes = {1: "192.168.0", **{v: f"192.168.{n + v}" for v in (10, 20, 30)}}
    router_ports = {v: ("Switch2", f"{prefixes[v]}.254") for v in prefixes}

    initial = [Trunk("Switch0", "Gi0/1", "Switch1", "Gi0/1", (10, 20)),
               Trunk("Switch1", "Gi0/2", "Switch2", "Gi0/1", (10, 30))]
    routed = [initial[0], Trunk("Switch1", "Gi0/2", "Switch2", "Gi0/1", (10, 20, 30))]
    all_vlans = [Trunk("Switch0", "Gi0/1", "Switch1", "Gi0/1", (1, 10, 20)),
                 Trunk("Switch1", "Gi0/2", "Switch2", "Gi0/1", (1, 10, 20, 30))]

    def hosts(gated):
        return {name: pc(name, sw, f"Fa0/{port}", vlan, f"{prefixes[vlan]}.{suffix}",
                         gateway=router_ports[vlan][1] if vlan in gated else None)
                for name, sw, port, vlan, suffix in order}

    without = hosts(())
    standard = hosts((10, 20, 30))
    complete = hosts((1, 10, 20, 30))
    test_pairs = [("PC11", "PC21"), ("PC11", "PC31"), ("PC12", "PC22"),
                  ("PC24", "PC34"), ("PC11", "PC12"), ("PC11", "PC34"),
                  ("PC14", "PC32"), ("PC14", "PC11")]
    before = lambda a, b: trace_lan(a, b, initial, {})
    after = lambda a, b: trace_lan(a, b, routed, {v: router_ports[v] for v in (10, 20, 30)})
    final = lambda a, b: trace_lan(a, b, all_vlans, router_ports)

    cases_without = ping_table(without, before, test_pairs)
    cases_routed = ping_table(standard, after, test_pairs)
    cases_complete = ping_table(complete, final, test_pairs)
    assert [row["received"] for row in cases_without] == [4, 4, 4, 4, 0, 0, 0, 0]
    assert [row["received"] for row in cases_routed] == [4, 4, 4, 4, 4, 4, 0, 0]
    all_tests = link_test_rows(complete, final)
    assert all(row["received"] == 4 for row in all_tests)

    for switch in ("Switch0", "Switch1", "Switch2"):
        lines = [f"hostname {switch}"]
        for v in (10, 20, 30):
            lines += [f"vlan {v}", f" name VLAN{v}", "exit"]
        for host in without.values():
            if host.switch == switch:
                lines += access(host.port, host.vlan)
        for trunk in initial:
            if switch == trunk.left:
                lines += trunk_ios(trunk.left_port, trunk.vlans)
            if switch == trunk.right:
                lines += trunk_ios(trunk.right_port, trunk.vlans)
        ios(out, f"lab2/01-access-trunk/{switch}.txt", lines)

    ios(out, "lab2/02-router-on-a-stick/Switch1.txt", trunk_ios("Gi0/2", (10, 20, 30)))
    ios(out, "lab2/02-router-on-a-stick/Switch2.txt",
        trunk_ios("Gi0/1", (10, 20, 30)) + trunk_ios("Gi0/2", (10, 20, 30)))
    lines = ["hostname Router0", "interface GigabitEthernet0/0", " no ip address",
             " no shutdown", "exit"]
    for v in (10, 20, 30):
        lines += [f"interface GigabitEthernet0/0.{v}", f" encapsulation dot1Q {v}",
                  f" ip address {router_ports[v][1]} {MASK24}", "exit"]
    ios(out, "lab2/02-router-on-a-stick/Router0.txt", lines)

    ios(out, "lab2/03-all-pcs/Switch0.txt", trunk_ios("Gi0/1", (1, 10, 20)))
    ios(out, "lab2/03-all-pcs/Switch1.txt",
        trunk_ios("Gi0/1", (1, 10, 20)) + trunk_ios("Gi0/2", (1, 10, 20, 30)))
    ios(out, "lab2/03-all-pcs/Switch2.txt",
        trunk_ios("Gi0/1", (1, 10, 20, 30)) + trunk_ios("Gi0/2", (1, 10, 20, 30)))
    ios(out, "lab2/03-all-pcs/Router0.txt", ["interface GigabitEthernet0/0.1",
        " encapsulation dot1Q 1 native", f" ip address {router_ports[1][1]} {MASK24}", "exit"])
    return {"pcs": pc_rows(complete), "gateway": {v: port[1] for v, port in router_ports.items()},
            "before": cases_without, "routed": cases_routed, "complete": cases_complete,
            "all_pairs": len(all_tests)}


@dataclass(frozen=True)
class Link:
    left: str
    left_port: str
    right: str
    right_port: str
    cost: int

    def peers(self):
        return ((self.left, self.left_port, self.right, self.right_port),
                (self.right, self.right_port, self.left, self.left_port))


def spanning_tree(links, bridge_ids):
    root = min(bridge_ids, key=bridge_ids.get)
    distance = {root: 0}
    work = [(0, root)]
    while work:
        cost, switch = heapq.heappop(work)
        if cost != distance[switch]:
            continue
        for link in links:
            for local, _, peer, _ in link.peers():
                if local == switch and cost + link.cost < distance.get(peer, float("inf")):
                    distance[peer] = cost + link.cost
                    heapq.heappush(work, (cost + link.cost, peer))

    upstream = {}
    for switch in distance:
        if switch == root:
            continue
        candidates = [(distance[peer] + link.cost, bridge_ids[peer], remote_port, local_port)
                      for link in links for local, local_port, peer, remote_port in link.peers()
                      if local == switch and peer in distance]
        upstream[switch] = min(candidates)[-1]

    rows = []
    forwarding = []
    for link in links:
        a, b = link.left, link.right
        if (distance[a], bridge_ids[a]) < (distance[b], bridge_ids[b]):
            designated = a
        else:
            designated = b
        roles = []
        for local, local_port, _, _ in link.peers():
            role = "Desg FWD" if local == designated else (
                "Root FWD" if upstream.get(local) == local_port else "Altn BLK")
            roles.append(role)
            rows.append((local, local_port, role))
        if all(role.endswith("FWD") for role in roles):
            forwarding.append(link)
    rows += [(sw, "Fa0/1", "Desg FWD (ПК)") for sw in bridge_ids]
    return root, sorted(rows), forwarding


def flood_rounds(links, limit=8):
    current = [("Switch0", None)]
    rounds = []
    for index in range(1, limit + 1):
        if not current:
            break
        following = []
        seen = Counter()
        for switch, origin in current:
            seen[switch] += 1
            for link in links:
                for local, local_port, node, remote_port in link.peers():
                    edge = (node, remote_port)
                    if local == switch and (switch, local_port) != origin:
                        following.append((node, edge))
        rounds.append({"round": index, "forwarded": len(following),
                       "switches": [f"{key} ×{seen[key]}" for key in sorted(seen)]})
        current = following
    return rounds


def lab3(n, out):
    s0, s1, s2 = ("Switch0", "Switch1", "Switch2")
    pcs = {f"PC{i}": pc(f"PC{i}", sw, "Fa0/1", 1, f"192.168.{n}.{i + 1}")
           for i, sw in enumerate((s0, s1, s2))}
    links = [Link(s0, "Fa0/2", s2, "Fa0/2", 19), Link(s0, "Fa0/4", s1, "Fa0/4", 19),
             Link(s1, "Fa0/5", s2, "Fa0/5", 19)]
    bridge_ids = {sw: (32769, f"02:00:00:00:00:0{i}") for i, sw in enumerate((s0, s1, s2))}
    root0, roles0, _ = spanning_tree(links, bridge_ids)
    bridge_ids[s2] = (24577, bridge_ids[s2][1])
    root1, roles1, _ = spanning_tree(links, bridge_ids)
    parallel = links + [Link(s0, "Fa0/3", s2, "Fa0/3", 19)]
    _, before_bundle, _ = spanning_tree(parallel, bridge_ids)
    bundle = [Link(s0, "Po1", s2, "Po1", 12), *links[1:]]
    _, roles_bundle, forwarding = spanning_tree(bundle, bridge_ids)
    surviving = [Link(s0, "Po1", s2, "Po1", 19), *links[1:]]
    _, roles_survivor, last_forwarding = spanning_tree(surviving, bridge_ids)

    def match(a, b, forwarding_links):
        trunks = [Trunk(x.left, x.left_port, x.right, x.right_port, (1,)) for x in forwarding_links]
        return trace_lan(a, b, trunks, {})

    success = ping_table(pcs, lambda a, b: match(a, b, forwarding), [("PC0", "PC2")])
    failure = ping_table(pcs, lambda a, b: match(a, b, last_forwarding), [("PC0", "PC2")])
    blocked = flood_rounds(last_forwarding)
    storm = flood_rounds(surviving)
    assert root0 == s0 and root1 == s2
    assert sum(r[2] == "Altn BLK" for r in before_bundle) == 2
    assert sum(r[2] == "Altn BLK" for r in roles_bundle) == 1
    assert success[0]["received"] == failure[0]["received"] == 4
    assert blocked[-1]["forwarded"] == 0 and storm[-1]["forwarded"] == 2

    for sw in bridge_ids:
        ios(out, f"lab3/01-initial/{sw}.txt", [f"hostname {sw}", "spanning-tree mode pvst"])
    ios(out, "lab3/02-root/Switch2.txt", ["spanning-tree vlan 1 root primary"])
    for sw in (s0, s2):
        ios(out, f"lab3/03-lacp/{sw}.txt", ["interface range FastEthernet0/2 - 3",
            " channel-group 1 mode active", "exit"])
    ios(out, "lab3/04-failure/Switch0.txt", ["interface FastEthernet0/3", " shutdown", "exit"])
    for sw in bridge_ids:
        ios(out, f"lab3/05-isolated-storm/{sw}.txt", ["no spanning-tree vlan 1"])
        ios(out, f"lab3/06-restore/{sw}.txt", ["spanning-tree vlan 1"])
    ios(out, "lab3/06-restore/Switch0-link.txt", ["interface FastEthernet0/3", " no shutdown", "exit"])
    return {"pcs": pc_rows(pcs), "root_before": root0, "root_after": root1,
            "priority_before": 32769, "priority_after": 24577, "macs": bridge_ids,
            "roles_initial": roles0, "roles_primary": roles1, "roles_parallel": before_bundle,
            "roles_bundle": roles_bundle, "roles_survivor": roles_survivor,
            "ping_ok": success[0], "ping_survivor": failure[0], "tree_flood": blocked, "storm": storm}

VARIANTS = {
    1: ("172.16.0.0/16", (200, 50, 500), "192.168"),
    2: ("10.0.0.0/16", (150, 700, 30), "172.16"),
    3: ("172.16.0.0/16", (300, 400, 100), "192.168"),
    4: ("192.168.0.0/16", (30, 450, 500), "172.16"),
    5: ("10.0.0.0/16", (130, 550, 230), "192.168"),
}


def split_vlsm(block, host_counts):
    pool = IPv4Network(block)
    current = int(pool.network_address)
    subnets = {}
    for idx in sorted(range(len(host_counts)), key=lambda i: -host_counts[i]):
        size = 1 << (host_counts[idx] + 1).bit_length()
        prefix = 32 - (size.bit_length() - 1)
        network = IPv4Network((current, prefix))
        if not network.subnet_of(pool):
            raise ValueError("Недостаточно адресов в исходном блоке")
        subnets[idx] = network
        current += size
    return [subnets[i] for i in range(len(host_counts))]


def classic_network(address):
    first = int(str(address).split(".")[0])
    prefix = 8 if first < 128 else 16 if first < 192 else 24
    return str(IPv4Network(f"{address}/{prefix}", strict=False).network_address)


@dataclass(frozen=True)
class Route:
    network: IPv4Network
    origin: str
    next_hop: str | None
    metric: int = 0


class DHCPPool:
    def __init__(self, network, gateway, excluded):
        self.network = network
        self.gateway = gateway
        self.excluded = set(excluded)
        self.bindings = {}
        self.offers = {}

    def discover(self, client):
        if client in self.bindings:
            address = self.bindings[client]
        elif client in self.offers:
            address = self.offers[client]
        else:
            used = self.excluded | set(self.bindings.values()) | set(self.offers.values())
            address = next((address for address in self.network.hosts() if address not in used), None)
            if address is None:
                raise RuntimeError("Нет свободных адресов в пуле")
        self.offers[client] = address
        return address

    def request(self, client, address):
        if self.offers.get(client) != address:
            raise ValueError("Запрошенный адрес не соответствует предложению")
        self.bindings[client] = self.offers.pop(client)
        return {"ip": str(address), "mask": str(self.network.netmask), "gateway": str(self.gateway)}


def lab4(n, out):
    variant = n % 5 + 1
    block, needs, transit_prefix = VARIANTS[variant]
    lans = split_vlsm(block, needs)
    names = ("Router0", "Router1", "Router2")
    transit = []
    mapping = {}

    for index, a, a_port, b, b_port in (
        (1, names[0], "Gi9/0", names[1], "Gi9/0"),
        (2, names[1], "Gi8/0", names[2], "Gi9/0"),
        (3, names[0], "Gi8/0", names[2], "Gi8/0"),
    ):
        net = IPv4Network(f"{transit_prefix}.{index}.0/24")
        aa, bb = (str(net.network_address + inc) for inc in (1, 2))
        transit.append({"network": str(net), "a": a, "a_port": a_port, "a_ip": aa,
                        "b": b, "b_port": b_port, "b_ip": bb})
        mapping[(a, b)] = bb
        mapping[(b, a)] = aa

    hosts = {}
    hardcoded, relayed = [], []
    base_routes = {name: [Route(lans[i], "C", None)] for i, name in enumerate(names)}
    for link in transit:
        for router in (link["a"], link["b"]):
            base_routes[router].append(Route(IPv4Network(link["network"]), "C", None))

    for i, (router, network) in enumerate(zip(names, lans)):
        first = network.network_address + 1
        last = network.broadcast_address - 1
        pool = DHCPPool(network, first, (first, last))
        client = f"PC{i * 2 + 1}"
        dynamic = pool.discover(client)
        ack = pool.request(client, dynamic)
        assert pool.discover(client) == dynamic
        assert dynamic == network.network_address + 2 and dynamic not in pool.excluded
        for j, addr in enumerate((last, dynamic)):
            name = f"PC{i * 2 + j}"
            hosts[name] = pc(name, f"Switch{i}", f"Fa0/{j+1}", i+1,
                             addr, network.prefixlen, str(first))
        hardcoded.append({"lan": i+1, "needs": needs[i], "network": str(network),
                          "mask": str(network.netmask), "gateway": str(first),
                          "last": str(last), "broadcast": str(network.broadcast_address),
                          "capacity": network.num_addresses - 2, "step": network.num_addresses})
        relayed.append({"pc": client, **ack, "exclude1": str(first), "exclude2": str(last),
                        "exchange": ["DISCOVER", f"OFFER {dynamic}", f"REQUEST {dynamic}",
                                     f"ACK {ack['ip']}"]})

        lines = [f"hostname {router}",
                 *interface("FastEthernet7/0", first, network.netmask)]
        for link in transit:
            if router == link["a"]:
                lines += interface(link["a_port"], link["a_ip"], MASK24)
            if router == link["b"]:
                lines += interface(link["b_port"], link["b_ip"], MASK24)
        ios(out, f"lab4/01-interfaces/{router}.txt", lines)
        ios(out, f"lab4/02-dhcp/{router}.txt", [
            "service dhcp", f"ip dhcp excluded-address {first}",
            f"ip dhcp excluded-address {last}", f"ip dhcp pool LAN{i+1}",
            f" network {network.network_address} {network.netmask}",
            f" default-router {first}", "exit"])

    routes = {router: list(rows) for router, rows in base_routes.items()}
    static_edges = {names[0]: (1,), names[1]: (0, 2), names[2]: (1,)}
    for router, indices in static_edges.items():
        lines = []
        for index in indices:
            network = lans[index]
            next_hop = mapping[(router, names[index])]
            routes[router].append(Route(network, "S", next_hop))
            lines.append(f"ip route {network.network_address} {network.netmask} {next_hop}")
        ios(out, f"lab4/03-static/{router}.txt", lines)

    connected_advertisements = {names[i]: [r.network for r in base_routes[names[i]]
                                           if r.network in lans] for i in (0, 2)}
    for local, remote in [(0, 2), (2, 0)]:
        router, neighbor = names[local], names[remote]
        for announced in connected_advertisements[neighbor]:
            routes[router].append(Route(announced, "R", mapping[(router, neighbor)], 1))
        rip_lan = classic_network(lans[local].network_address + 1)
        rip_transit = classic_network(transit[-1]["network"].split("/")[0])
        ios(out, f"lab4/04-ripv2/{router}.txt", ["router rip", " version 2",
            " no auto-summary", " passive-interface FastEthernet7/0", " passive-interface GigabitEthernet9/0",
            f" network {rip_lan}", f" network {rip_transit}", "exit"])

    by_neighbor = {key: hop for key, hop in mapping.items()}

    def trace(a, b, entries):
        if a.vlan == b.vlan:
            return [a.name, a.switch, b.name]
        router = names[a.vlan - 1]
        path = [a.name, a.switch]
        visited = set()
        while router not in visited:
            path.append(router)
            visited.add(router)
            covering = [r for r in entries[router] if b.address.ip in r.network]
            if not covering:
                return None
            code = {"C": 0, "S": 1, "R": 120}
            route = min(covering, key=lambda r: (-r.network.prefixlen, code[r.origin], r.metric))
            if route.next_hop is None:
                return [*path, b.switch, b.name] if router == names[b.vlan-1] else None
            router = next(peer for peer in names if by_neighbor.get((router, peer)) == route.next_hop)
        return None

    cross_pairs = [("PC1", "PC2"), ("PC2", "PC1"), ("PC3", "PC4"),
                   ("PC4", "PC3"), ("PC0", "PC4"), ("PC4", "PC0")]
    route_rows = ping_table(hosts, lambda a,b: trace(a,b,routes), cross_pairs)
    assert all(row["received"] == 4 for row in link_test_rows(hosts, lambda a,b: trace(a,b,routes)))
    initial = ping_table(hosts, lambda a,b: trace(a,b,base_routes),
                         [("PC0","PC1"), ("PC1","PC3"), ("PC0","PC4")])
    assert [x["received"] for x in initial] == [4, 0, 0]
    lan_routes = [{"router": router, "path": str(route.network), "type": route.origin,
                   "next": route.next_hop, "metric": route.metric}
                  for router, table in routes.items() for route in table
                  if route.network in lans]
    return {"variant": variant, "block": block, "lans": hardcoded, "transit": transit,
            "pcs": pc_rows(hosts), "dhcp": relayed, "before_routes": initial,
            "routes": lan_routes, "results": route_rows}


def run(number, output):
    if not 1 <= number <= 225:
        raise ValueError("Номер в журнале должен быть от 1 до 225 для заданной адресации")
    target = output / "cisco"
    result = {"number": number,
              "lab1": lab1(number, target),
              "lab2": lab2(number, target),
              "lab3": lab3(number, target),
              "lab4": lab4(number, target)}
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Вычисление адресации и проверка четырёх учебных стендов")
    parser.add_argument("--number", type=int, required=True, help="порядковый номер в журнале")
    parser.add_argument("--out", type=Path, default=Path("result"), help="каталог конфигураций и результатов")
    args = parser.parse_args()
    result = run(args.number, args.out)
    print(f"N={result['number']}, лабораторная № 4: вариант {result['lab4']['variant']}")
    print("ЛР 1: два сегмента и маршрутизация между ними.")
    print(f"ЛР 2: за три этапа проверены VLAN, Router-on-a-stick и {result['lab2']['all_pairs']} направлений между ПК.")
    print(f"ЛР 3: корень {result['lab3']['root_before']} → {result['lab3']['root_after']}; проверены LACP, отказ и цикл.")
    print("ЛР 4: разбиение VLSM и получение параметров DHCP; проверены статические и RIP-маршруты.")
    print(f"Каталог: {args.out}")


if __name__ == "__main__":
    main()
