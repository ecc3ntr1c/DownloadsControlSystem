"""Build 8.2.1-format Packet Tracer files for the four networking labs."""

import argparse
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

from pkt_core import Lab, decode

from stand import run


ASSETS = Path(__file__).with_name("templates")
SWITCH = "2960-24TT"
PC = "PC-PT"
FAST = "FastEthernet"
GIG = "GigabitEthernet"


def full_interface(name):
    if name.startswith("Fa") and name[2].isdigit():
        return FAST + name[2:]
    if name.startswith("Gi") and name[2].isdigit():
        return GIG + name[2:]
    return name


def set_value(parent, tag, value):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    el.text = value


def replace_command(cmds, line):
    key = next((p for p in ("ip address", "switchport mode", "switchport access vlan",
                            "switchport trunk allowed vlan", "spanning-tree mode")
                if line.startswith(p + " ")), line)
    conflicting = {line}
    if line in ("shutdown", "no shutdown"):
        conflicting.update(("shutdown", "no shutdown"))
    if key == "ip address" or line == "no ip address":
        conflicting.add("no ip address")
        key = "ip address"
    cmds[:] = [x for x in cmds if x not in conflicting and not x.startswith(key + " ")]
    cmds.append(line)


def write_config(engine, name, scripts):
    """Turn CLI input into saved running-config blocks, preserving template defaults."""
    rc = engine.find("RUNNINGCONFIG")
    model = engine.find("TYPE").get("model")
    globals_ = []
    interfaces = {}
    sections = {}
    current = globals_
    for el in rc.findall("LINE"):
        line = el.text or ""
        if line.startswith("interface "):
            current = interfaces.setdefault(line[10:], [])
        elif line.startswith("line "):
            current = sections.setdefault(line, [])
        elif line.startswith(" "):
            current.append(line.strip())
        else:
            current = globals_
            if line and line not in ("!", "end") and not line.startswith("hostname "):
                globals_.append(line)
    set_value(engine, "SYS_NAME", name)

    vlans = {}
    for script in scripts:
        blocks = []
        for raw in script.splitlines():
            line = raw.strip()
            if not line or line in ("enable", "configure terminal", "end") or line.startswith("hostname "):
                continue
            if raw.startswith(" "):
                if line == "no ip address" or not blocks:
                    continue
                for block in blocks:
                    replace_command(block, line)
            elif line == "exit":
                blocks = []
            elif line.startswith("interface range "):
                match = re.fullmatch(r"(FastEthernet\d+/)(\d+)\s*-\s*(\d+)", line[16:])
                if not match:
                    raise ValueError(line)
                prefix, start, end = match.groups()
                blocks = [interfaces.setdefault(prefix + str(i), [])
                          for i in range(int(start), int(end) + 1)]
                interfaces.setdefault("Port-channel1", [])
            elif line.startswith("interface "):
                iface = full_interface(line[10:])
                commands = interfaces.setdefault(iface, [])
                if model == "Router-PT-Empty" and iface.startswith((FAST, GIG)):
                    for option in ("duplex auto", "speed auto"):
                        if option not in commands:
                            commands.append(option)
                blocks = [commands]
            elif line.startswith("vlan "):
                vlan = int(line[5:])
                vlans[vlan] = []
                blocks = [vlans[vlan]]
            elif line.startswith(("ip dhcp pool ", "router rip")):
                blocks = [sections.setdefault(line, [])]
            else:
                if line == "spanning-tree vlan 1 root primary":
                    line = "spanning-tree vlan 1 priority 24576"
                if line != "service dhcp":
                    replace_command(globals_, line)
                blocks = []

    if vlans:
        tag = engine.find("VLANS")
        for vlan, commands in vlans.items():
            vlan_name = next((x[5:] for x in commands if x.startswith("name ")), f"VLAN{vlan:04}")
            ET.SubElement(tag, "VLAN", name=vlan_name, number=str(vlan), rspan="0")

    # A saved running config has mode separators and no EXEC input.
    # no shutdown is represented by omitting shutdown from an up interface.
    output = ["!"]
    for line in globals_:
        output.append(line)
        if line == "no service password-encryption":
            output.extend(("!", f"hostname {name}", "!"))
    dhcp = {k: v for k, v in sections.items() if k.startswith("ip dhcp pool ")}
    other = {k: v for k, v in sections.items() if k not in dhcp and not k.startswith("line ")}
    tty = {k: v for k, v in sections.items() if k.startswith("line ")}
    interface_blocks = {f"interface {name}": commands for name, commands in interfaces.items()}
    for mapping in (dhcp, interface_blocks, other, tty):
        for title, commands in mapping.items():
            output.extend(("!", title))
            output.extend(" " + c for c in commands if c != "no shutdown")
    output.extend(("!", "end"))
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        config = engine.find(tag)
        if config is None:
            config = ET.SubElement(engine, tag)
        for el in list(config):
            config.remove(el)
        for line in output:
            ET.SubElement(config, "LINE").text = line
    return interfaces


def hardware_ports(engine):
    model = engine.find("TYPE").get("model")
    ports = list(engine.iter("PORT"))
    if model == SWITCH:
        names = [FAST + f"0/{i}" for i in range(1, 25)] + [GIG + "0/1", GIG + "0/2"]
    elif model == "2811":
        names = [FAST + "0/0", FAST + "0/1"]
    elif model == "2901":
        names = [GIG + "0/0", GIG + "0/1"]
    elif model == "Router-PT-Empty":
        names = [FAST + "7/0", GIG + "8/0", GIG + "9/0"]
    elif model == PC:
        names, ports = [FAST + "0"], ports[:1]
    else:
        raise ValueError(f"Unknown device model {model}")
    assert len(names) == len(ports), (model, len(names), len(ports))
    return dict(zip(names, ports))


class Network:
    def __init__(self, config):
        self.lab = Lab(ASSETS / "skeleton.pkt",
                       models={p.stem: p.read_bytes() for p in ASSETS.glob("*.xml")})
        self.lab.prune_seed_devices()
        self.config = config
        self.ids = {}
        self.models = {}
        self.used_ports = set()
        self.ports = {}
        self.links = []
        self.lab.base.find("COMMAND_LOGS").clear()
        profile = self.lab.base.find("USER_PROFILE")
        set_value(profile, "NAME", "Gorokhov A.S.")
        for tag in ("EMAIL", "ADDITIONAL_INFO"):
            existing = profile.find(tag)
            if existing is not None:
                existing.text = ""
        set_value(self.lab.base.find("OPTIONS"), "SHOW_DEV_MODEL_LABEL", "true")

    def add(self, model, name, position, stages=(), host=None, gateway=None, dhcp=False,
            extra=""):
        if host is None:
            ip = None
        elif dhcp:
            ip = ("", "", "")
        else:
            ip = (host["ip"], host["mask"], gateway or "")
        sid = self.lab.add_device(model, name, *position, pc_ip=ip)
        self.ids[name] = sid
        self.models[name] = model
        engine = self.lab._els[sid].find("ENGINE")
        if model == "Router-PT-Empty":
            self.install_router_ports(engine)
        self.ports[name] = hardware_ports(engine)
        if host is not None:
            set_value(engine, "SYS_NAME", name)
            tag = engine.find("DNS_CLIENT/SERVER_IP")
            if tag is not None:
                tag.text = ""
            if dhcp:
                set_value(self.ports[name][FAST + "0"], "PORT_DHCP_ENABLE", "true")
                dhcp_map = engine.find("DHCP_CLIENT/PORT_DATA_MAP")
                entry = ET.SubElement(dhcp_map, "PORT_DATA_ENTRY")
                set_value(entry, "PORT", FAST + "0")
            return
        archive = [self.config / s / f"{name}.txt" for s in stages]
        scripts = [p.read_text() for p in archive if p.is_file()]
        if extra:
            scripts.append(extra)
        port_commands = write_config(engine, name, scripts)
        set_value(engine, "BUILD_IN_ADDR", next(iter(self.ports[name].values())).findtext("MACADDRESS"))
        for interface, port in self.ports[name].items():
            commands = port_commands.get(interface, [])
            power_up = "shutdown" not in commands and (model == SWITCH or "no shutdown" in commands)
            set_value(port, "POWER", str(power_up).lower())
            for command in commands:
                if command.startswith("ip address "):
                    _, _, address, mask = command.split()
                    set_value(port, "IP", address)
                    set_value(port, "SUBNET", mask)

    def install_router_ports(self, engine):
        # These three modules are compatible with the generic PT chassis.
        donor = self.lab.models["Router-PT"]
        fast = ET.fromstring(donor).find(".//SLOT/MODULE[MODEL='PT-ROUTER-NM-1CFE']")
        giga_port = ET.fromstring(self.lab.models["2901"]).find(".//PORT")
        slots = [s for s in engine.iter("SLOT") if s.findtext("TYPE") == "ePtRouterModule"]
        for slot in (7, 8, 9):
            module = deepcopy(fast)
            if slot in (8, 9):
                set_value(module, "MODEL", "PT-ROUTER-NM-1CGE")
                module.remove(module.find("PORT"))
                module.append(deepcopy(giga_port))
                set_value(module.find("PORT"), "BANDWIDTH", "1000000")
            mac = self.lab._next_mac()
            for tag in ("MACADDRESS", "BIA"):
                set_value(module.find("PORT"), tag, mac)
            slots[slot].append(module)

    def link(self, a, ap, b, bp):
        ap, bp = full_interface(ap), full_interface(bp)
        for name, port in ((a, ap), (b, bp)):
            assert port in self.ports[name], (name, port)
            assert (name, port) not in self.used_ports, (name, port)
            self.used_ports.add((name, port))
        self.lab.link(self.ids[a], ap, self.ids[b], bp)
        # Both copper kinds use eCopper; the nested cable stores the subtype.
        routers = {"2811", "2901", "Router-PT-Empty"}
        if self.models[a] == self.models[b] or {self.models[a], self.models[b]} <= routers:
            entry = list(self.lab.net.find("LINKS"))[-1]
            set_value(entry.find("CABLE"), "TYPE", "eCrossOver")
        self.links.append((a, ap, b, bp))

    def host(self, h, xy, gateway=True, dhcp=False):
        self.add(PC, h["pc"], xy, host=h, gateway=h.get("gateway") if gateway else None, dhcp=dhcp)
        self.link(h["pc"], FAST + "0", h["switch"], h["port"])

    def save(self, out, name):
        target = out / f"{name}.pkt"
        self.lab.save(target)
        # Check the actual saved bytes, endpoint ownership and count.
        parsed = ET.fromstring(decode(target).xml)
        assert parsed.findtext("VERSION") == "8.2.1.0118"
        engines = parsed.findall("NETWORK/DEVICES/DEVICE/ENGINE")
        assert {e.findtext("SAVE_REF_ID"): e.findtext("NAME") for e in engines} == {
            sid: name for name, sid in self.ids.items()
        }
        read_links = parsed.findall("NETWORK/LINKS/LINK/CABLE")
        assert [
            (e.findtext("FROM"), *[p.text for p in e.findall("PORT")], e.findtext("TO"))
            for e in read_links
        ] == [(self.ids[a], ap, bp, self.ids[b]) for a, ap, b, bp in self.links]
        print(f"{target.name}: {len(engines)} devices, {len(read_links)} links")


def lab1(config, d, out):
    n = Network(config / "lab1")
    for s, x in enumerate((300, 810)):
        n.add(SWITCH, f"Switch{s}", (x, 340), (".",))
    n.add("2811", "Router0", (555, 180), (".",))
    for iface, _, sw, port in d["router"]:
        n.link("Router0", iface, sw, port)
    for h, x in zip(d["pcs"], (90, 225, 360, 495, 715, 905)):
        n.host(h, (x, 520))
    n.save(out, "01_IPv4")


def lab2(config, d, out):
    stages = ("01-access-trunk", "02-router-on-a-stick", "03-all-pcs")
    for phase, output in enumerate(("02a_VLAN_only", "02b_Router_on_a_stick", "02c_All_VLAN")):
        n = Network(config / "lab2")
        for i, y in enumerate((170, 355, 540)):
            n.add(SWITCH, f"Switch{i}", (555, y), stages[:phase + 1])
        n.link("Switch0", "Gi0/1", "Switch1", "Gi0/1")
        n.link("Switch1", "Gi0/2", "Switch2", "Gi0/1")
        labels = {sw: ["PC11", "PC12", "PC13", "PC14"] if sw == "Switch0" else
                  ["PC21", "PC22", "PC23", "PC24", "PC25"] if sw == "Switch1" else
                  ["PC31", "PC32", "PC34", "PC35"] for sw in n.ids}
        floor = {"Switch0": 130, "Switch1": 315, "Switch2": 500}
        x_coords = (130, 322, 780, 970, 1115)
        for h in d["pcs"]:
            x = x_coords[labels[h["switch"]].index(h["pc"])]
            n.host(h, (x, floor[h["switch"]]), gateway=phase == 2 or (phase == 1 and h["vlan"] != 1))
        if phase:
            n.add("2901", "Router0", (555, 710), stages[1:phase + 1])
            n.link("Switch2", "Gi0/2", "Router0", "Gi0/0")
        n.save(out, output)


def lab3(config, d, out):
    stages = ("01-initial", "02-root", "03-lacp", "04-failure", "05-isolated-storm")
    phases = [
        ("03a_STP_initial", stages[:1], False),
        ("03b_STP_new_root", stages[:2], False),
        ("03c_LACP", stages[:3], True),
        ("03d_LACP_link_down", stages[:4], True),
        ("03e_STP_loop_Isolated", (stages[0], stages[4]), False),
    ]
    for output, config_stages, parallel in phases:
        n = Network(config / "lab3")
        storm = config_stages[-1] == stages[-1]
        for i, xy in enumerate(((345, 490), (790, 490), (570, 170))):
            n.add(SWITCH, f"Switch{i}", xy, config_stages, extra="no cdp run" if storm else "")
        n.link("Switch0", "Fa0/2", "Switch2", "Fa0/2")
        n.link("Switch0", "Fa0/4", "Switch1", "Fa0/4")
        n.link("Switch1", "Fa0/5", "Switch2", "Fa0/5")
        if parallel:
            n.link("Switch0", "Fa0/3", "Switch2", "Fa0/3")
        for h, xy in zip(d["pcs"], ((130, 490), (1000, 490), (820, 170))):
            n.host(h, xy, gateway=False)
        n.save(out, output)


def lab4(config, d, out):
    stages = ("01-interfaces", "02-dhcp", "03-static", "04-ripv2")
    for depth, label in ((3, "04a_DHCP_static"), (4, "04b_DHCP_static_RIPv2")):
        n = Network(config / "lab4")
        router_xy = ((300, 440), (600, 150), (900, 440))
        switch_xy = ((290, 590), (600, 330), (910, 590))
        for i, (router, switch) in enumerate(zip(router_xy, switch_xy)):
            n.add("Router-PT-Empty", f"Router{i}", router, stages[:depth])
            n.add(SWITCH, f"Switch{i}", switch)
            n.link(f"Router{i}", "Fa7/0", f"Switch{i}", "Fa0/24")
        for t in d["transit"]:
            n.link(t["a"], t["a_port"], t["b"], t["b_port"])
        dynamic = {r["pc"] for r in d["dhcp"]}
        xy = ((170, 735), (360, 735), (492, 430), (700, 430), (840, 735), (1030, 735))
        for h, position in zip(d["pcs"], xy):
            n.host(h, position, dhcp=h["pc"] in dynamic)
        n.save(out, label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--number", type=int, default=3, help="student's position in the group journal")
    parser.add_argument("--out", type=Path, default=Path("pkt"), help="output folder")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as spool:
        work = Path(spool)
        d = run(args.number, work)
        for i, build in enumerate((lab1, lab2, lab3, lab4), 1):
            build(work / "cisco", d[f"lab{i}"], args.out)
        (args.out / "addresses.json").write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"N = {args.number}, lab 4 variant {d['lab4']['variant']}")


if __name__ == "__main__":
    main()
