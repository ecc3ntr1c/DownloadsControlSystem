#!/usr/bin/env python3
"""Build the all-four-labs report from supplied requirements and verified evidence.

Authoring gate: the parent agent must run mark_artifact_operation_started.mjs
once before invoking this script. Preparing/compiling this script is read-only
with respect to the report. Use the bundled Python runtime.

    python build_report.py --manifest report_manifest.json --strict

The source DOCX is retained unchanged. Model images/results are never copied.
Only address/configuration parameters are taken from the two addresses JSONs.
All claims about observed outcomes come from the separately supplied manifest.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from PIL import Image

HERE = Path(__file__).resolve().parent
BASE = HERE / "Setevye_Tehnologii_Codex"
SOURCE = BASE / "report/Setevye_Tehnologii_Lab_01-04_Gorokhov.docx"
DEFAULT_OUT = HERE / "final/Setevye_Tehnologii_Gorokhov.docx"

SLOTS = {
    "1": ["topology", "configuration", "checks"],
    "2": ["topology", "access", "trunk", "isolation", "routing", "checks"],
    "3": ["topology", "stp_initial", "stp_root", "lacp", "failure", "storm", "checks"],
    "4": ["topology", "interfaces", "dhcp", "static", "rip", "checks"],
}


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def set_font(style, size, bold=False):
    style.font.name = "Times New Roman"
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = RGBColor(0, 0, 0)
    rf = style.element.get_or_add_rPr().get_or_add_rFonts()
    for key in ("ascii", "hAnsi", "eastAsia", "cs"):
        rf.set(qn("w:" + key), "Times New Roman")


def clear_paragraph_border(paragraph):
    prop = paragraph._p.find(qn("w:pPr"))
    if prop is not None:
        for border in prop.findall(qn("w:pBdr")):
            prop.remove(border)


def source_questions(source):
    # Stable source-specific paragraph ranges; assert counts to fail on drift.
    ranges = {1: (39, 65), 2: (82, 98), 3: (120, 130), 4: (161, 193)}
    out = {}
    for lab, (start, end) in ranges.items():
        items = []
        for i in range(start, end):
            text = source.paragraphs[i].text.strip()
            if re.match(r"^\d+\. ", text):
                answer = source.paragraphs[i + 1].text.strip()
                items.append((text, answer))
        out[lab] = items
    assert [len(out[i]) for i in range(1, 5)] == [12, 8, 5, 15]
    out[1][7] = (
        out[1][7][0],
        "По способу задания пути различают жёсткую и свободную маршрутизацию от источника. "
        "При жёсткой задаётся точная последовательность промежуточных узлов; при свободной "
        "задаются обязательные узлы, между которыми допустимы другие маршрутизаторы. "
        "По способу формирования таблиц различают статическую и динамическую маршрутизацию: "
        "в первом случае записи задаёт администратор, во втором их изучает протокол маршрутизации. "
        "Подключённые маршруты появляются по работающим интерфейсам, а маршрут по умолчанию "
        "используется при отсутствии более точного совпадения.",
    )
    return out


class Report:
    def __init__(self, manifest, strict=False):
        self.manifest = manifest
        self.strict = strict
        self.source = Document(SOURCE)
        self.doc = Document(SOURCE)  # preserve source page geometry and style system
        self.qa = source_questions(self.source)
        self.data = load_json(BASE / "packet-tracer/verified_inputs/addresses_N4.json")
        self.lab4 = load_json(BASE / "packet-tracer/pkt/addresses.json")["lab4"]
        assert self.data["number"] == 4
        assert self.lab4["variant"] == 4
        self.figures = defaultdict(int)
        self.inserted = set()
        self.shots_dir = Path(manifest.get("screenshots_dir", BASE / "screenshots"))
        if not self.shots_dir.is_absolute():
            self.shots_dir = HERE / self.shots_dir
        # Preserve the eight source title paragraphs, discard the obsolete body.
        body = self.doc._element.body
        title_nodes = [deepcopy(p._p) for p in self.source.paragraphs[:8]]
        section = deepcopy(body.sectPr)
        for child in list(body):
            body.remove(child)
        for child in title_nodes:
            body.append(child)
        body.append(section)
        self.configure_styles()
        self.doc.core_properties.title = "Сетевые технологии Отчёт по лабораторным работам 1–4"
        self.doc.core_properties.subject = "IPv4, VLAN, STP, EtherChannel, DHCP и маршрутизация"
        self.doc.core_properties.author = "Горохов А.С."
        self.doc.core_properties.keywords = "Сетевые технологии; Cisco Packet Tracer; БСТ 2457"
        self.doc.core_properties.comments = ""

    def configure_styles(self):
        d = self.doc
        set_font(d.styles["Normal"], 12)
        normal = d.styles["Normal"].paragraph_format
        normal.line_spacing = 1.08
        normal.space_after = Pt(5)
        normal.widow_control = True
        normal.keep_with_next = False
        for name, size in [("Title", 14), ("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 12)]:
            set_font(d.styles[name], size, True)
            p = d.styles[name].paragraph_format
            p.keep_with_next = True
            p.space_before = Pt(10 if name != "Title" else 0)
            p.space_after = Pt(6)
            p.line_spacing = 1.05
            prop = d.styles[name].element.find(qn("w:pPr"))
            if prop is not None:
                for border in prop.findall(qn("w:pBdr")):
                    prop.remove(border)
        for name in ("Report Code", "Report Caption", "Report Table", "Report Question"):
            if name not in d.styles:
                d.styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
        set_font(d.styles["Report Caption"], 10)
        caption = d.styles["Report Caption"].paragraph_format
        caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
        caption.space_before = Pt(3)
        caption.space_after = Pt(8)
        caption.line_spacing = 1
        caption.keep_together = True
        set_font(d.styles["Report Table"], 10.5)
        table = d.styles["Report Table"].paragraph_format
        table.space_before = Pt(0)
        table.space_after = Pt(3)
        table.line_spacing = 1
        set_font(d.styles["Report Question"], 12, True)
        question = d.styles["Report Question"].paragraph_format
        question.space_before = Pt(7)
        question.space_after = Pt(3)
        question.keep_with_next = True
        code = d.styles["Report Code"]
        code.font.name = "Courier New"
        code.font.size = Pt(9.5)
        code.font.color.rgb = RGBColor(0, 0, 0)
        code.paragraph_format.line_spacing = 1
        code.paragraph_format.space_after = Pt(7)
        code.paragraph_format.keep_together = True
        code.paragraph_format.left_indent = Cm(.25)
        for p in d.paragraphs:
            clear_paragraph_border(p)
        # Retain title page geometry and the report's existing unobtrusive footer.
        for s in d.sections:
            s.different_first_page_header_footer = True
            s.first_page_footer.paragraphs[0].text = ""
        settings = d.settings.element
        update = settings.find(qn("w:updateFields"))
        if update is None:
            update = OxmlElement("w:updateFields")
            settings.append(update)
        update.set(qn("w:val"), "true")

    def p(self, text, style=None):
        p = self.doc.add_paragraph(str(text), style)
        if style is None:
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.keep_together = len(str(text)) <= 550
            p.paragraph_format.keep_with_next = str(text).endswith(":")
        return p

    def h(self, text, level=2, page=False):
        p = self.doc.add_paragraph(text, f"Heading {level}")
        if page:
            p.paragraph_format.page_break_before = True
        return p

    def code(self, text):
        return self.p(text.strip(), "Report Code")

    def table(self, headers, rows, widths=None):
        rows = list(rows)
        if self.doc.paragraphs and self.doc.paragraphs[-1].text.strip():
            self.doc.paragraphs[-1].paragraph_format.keep_with_next = True
        t = self.doc.add_table(rows=1, cols=len(headers))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        total = self.doc.sections[0].page_width.cm - self.doc.sections[0].left_margin.cm - self.doc.sections[0].right_margin.cm
        widths = widths or [total / len(headers)] * len(headers)
        factor = total / sum(widths)
        widths = [w * factor for w in widths]
        for i, width in enumerate(widths):
            t.columns[i].width = Cm(width)
        for n, values in enumerate([headers] + rows):
            row = t.rows[0] if n == 0 else t.add_row()
            trPr = row._tr.get_or_add_trPr()
            trPr.append(OxmlElement("w:cantSplit"))
            if n == 0:
                trPr.append(OxmlElement("w:tblHeader"))
            for i, value in enumerate(values):
                cell = row.cells[i]
                cell.width = Cm(widths[i])
                cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
                cell.text = str(value)
                for p in cell.paragraphs:
                    p.style = self.doc.styles["Report Table"]
                    # Keep short tables intact; long inventories may paginate
                    # between complete rows with their repeated header.
                    p.paragraph_format.keep_with_next = n == 0 or (len(rows) <= 14 and n < len(rows))
                    for run in p.runs:
                        run.bold = n == 0
                tcPr = cell._tc.get_or_add_tcPr()
                margins = OxmlElement("w:tcMar")
                for side in ("top", "left", "bottom", "right"):
                    m = OxmlElement("w:" + side)
                    m.set(qn("w:w"), "70")
                    m.set(qn("w:type"), "dxa")
                    margins.append(m)
                tcPr.append(margins)
                if n == 0:
                    shade = OxmlElement("w:shd")
                    shade.set(qn("w:fill"), "EEEEEE")
                    tcPr.append(shade)
        tblPr = t._tbl.tblPr
        borders = OxmlElement("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            edge = OxmlElement("w:" + side)
            edge.set(qn("w:val"), "single")
            edge.set(qn("w:sz"), "4")
            edge.set(qn("w:color"), "A0A0A0")
            borders.append(edge)
        tblPr.append(borders)
        self.p("").paragraph_format.space_after = Pt(1)
        return t

    def evidence(self, lab, slot):
        record = self.manifest.get("labs", {}).get(str(lab), {})
        for text in record.get("slot_observations", {}).get(slot, []):
            self.p(text)
        for table in record.get("slot_tables", {}).get(slot, []):
            if table.get("title"):
                self.h(table["title"], 3)
            self.table(table["headers"], table["rows"], table.get("widths"))
        for i, item in enumerate(record.get("screenshots", [])):
            if item.get("slot", "checks") != slot:
                continue
            path = Path(item["file"])
            if not path.is_absolute():
                path = self.shots_dir / path
            if not path.exists():
                raise FileNotFoundError(path)
            self.figures[lab] += 1
            self.inserted.add((str(lab), i))
            if item.get("before"):
                self.p(item["before"])
            p = self.doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.keep_with_next = True
            p.paragraph_format.space_after = Pt(0)
            if item.get("page_break_before"):
                p.paragraph_format.page_break_before = True
            with Image.open(path) as im:
                w, h = im.size
            max_w = item.get("width_cm", 17.1)
            max_h = item.get("max_height_cm", 11.4)
            actual_w = min(max_w, max_h * w / h)
            shape = p.add_run().add_picture(str(path), width=Cm(actual_w))
            shape._inline.docPr.set("descr", item["caption"])
            caption = self.p(f"Рисунок {lab}.{self.figures[lab]} — {item['caption']}", "Report Caption")
            caption.paragraph_format.keep_with_next = bool(item.get("note"))
            if item.get("note"):
                self.p(item["note"])

    def results(self, lab):
        data = self.manifest.get("labs", {}).get(str(lab), {})
        if data.get("observations") or data.get("results") or data.get("conclusion"):
            self.h("Анализ результатов")
        for text in data.get("observations", []):
            self.p(text)
        result = data.get("results")
        if result:
            self.table(result["headers"], result["rows"], result.get("widths"))
        for extra in data.get("tables", []):
            if extra.get("title"):
                self.h(extra["title"], 3)
            self.table(extra["headers"], extra["rows"], extra.get("widths"))
        if data.get("conclusion"):
            self.p("Вывод. " + data["conclusion"])

    def questions(self, lab):
        self.h("Контрольные вопросы")
        for question, answer in self.qa[lab]:
            self.p(question, "Report Question")
            self.p(answer)

    def opening(self):
        self.h("Исходные данные и состав отчёта", 1, page=True)
        self.p("Отчёт включает четыре работы по дисциплине «Сетевые технологии»: построение "
               "IPv4-сети, настройку VLAN, исследование STP и EtherChannel, а также настройку DHCP "
               "и статической и динамической маршрутизации. Для каждой работы приведены адресный план, "
               "основные действия, снимки экрана, результаты проверок и ответы на контрольные вопросы.")
        version = self.manifest.get("packet_tracer_version", "9.0.1")
        self.p(f"Среда выполнения — Cisco Packet Tracer {version} для macOS. "
               "В работах 1–3 используется номер N = 4. Для работы 4 задан вариант 4 "
               "с адресным блоком 192.168.0.0/16. Работа 4 соответствует практической работе 7 "
               "в исходной методичке.")
        self.h("Состав работ")
        for title in [
            "1. Построение простой сети с использованием симулятора компьютерных сетей.",
            "2. Изучение технологии виртуальных локальных сетей VLAN.",
            "3. Отказоустойчивость на основе STP и агрегации каналов.",
            "4. Статическая и динамическая маршрутизация и настройка DHCP.",
        ]:
            self.p(title)
        self.p("Первый ICMP-запрос после изменения конфигурации может потребовать разрешения "
               "ARP и ожидания сходимости протоколов. В разделе каждой работы указаны фактически "
               "зафиксированные результаты соответствующих проверок.")

    def lab1(self):
        self.h("Лабораторная работа 1", 1, page=True)
        self.h("Построение простой сети")
        self.p("Цель — построить сеть из двух IPv4-подсетей, настроить адреса и шлюзы "
               "и проверить обмен внутри сегментов и между ними.")
        self.p("Задание — соединить шесть ПК, два коммутатора Cisco 2960 и маршрутизатор Cisco 2811. "
               "PC1–PC4 подключаются к Switch0, PC5–PC6 — к Switch1. Маршрутизатор соединяет подсети "
               "192.168.4.0/24 и 192.168.5.0/24.")
        self.evidence(1, "topology")
        self.h("Адресация и настройка")
        self.p("На ПК используется FastEthernet0 и маска 255.255.255.0. Шлюзом служит "
               "интерфейс Router0 в соответствующей подсети. Соединения от маршрутизатора "
               "подключаются к Fa0/24 коммутаторов.")
        self.table(["ПК", "Коммутатор и порт", "IPv4", "Шлюз"],
                   [[p["pc"], p["switch"] + " " + p["port"], p["ip"], p["gateway"]] for p in self.data["lab1"]["pcs"]], [1.2, 4.3, 4, 4])
        self.code("""enable
configure terminal
interface FastEthernet0/0
 ip address 192.168.4.254 255.255.255.0
 no shutdown
exit
interface FastEthernet0/1
 ip address 192.168.5.254 255.255.255.0
 no shutdown
end""")
        self.evidence(1, "configuration")
        self.h("Проверка связи")
        self.p("Проверка включает ping и Simple PDU внутри одной подсети и между подсетями. "
               "Для обмена внутри LAN кадр передаётся получателю через коммутатор. Для другой "
               "подсети ПК передаёт кадр своему шлюзу. Обе сети подключены к Router0 напрямую, "
               "поэтому дополнительные статические маршруты не требуются.")
        self.evidence(1, "checks")
        self.results(1)
        self.questions(1)

    def lab2(self):
        self.h("Лабораторная работа 2", 1, page=True)
        self.h("Виртуальные локальные сети VLAN")
        self.p("Цель — настроить access- и trunk-порты, проверить изоляцию VLAN и организовать "
               "маршрутизацию между ними по схеме Router-on-a-stick.")
        self.p("Задание — построить сеть трёх этажей с 13 ПК и тремя Cisco 2960. "
               "На первом этапе маршрутизатор отсутствует; на втором к Switch2 добавляется Cisco 2901 Router0.")
        self.evidence(2, "topology")
        self.h("Адресация и распределение портов")
        self.p("VLAN 10, 20 и 30 используют сети 192.168.14.0/24, 192.168.24.0/24 и "
               "192.168.34.0/24. PC14 и PC32 относятся к VLAN 1 с сетью 192.168.0.0/24. "
               "До подключения Router0 шлюзы не назначаются.")
        self.table(["ПК", "Коммутатор и порт", "VLAN", "IPv4 /24"],
                   [[p["pc"], p["switch"] + " " + p["port"], p["vlan"], p["ip"]] for p in self.data["lab2"]["pcs"]], [1.7, 5.2, 1.5, 4])
        self.h("Настройка access и trunk")
        self.p("Access-порты связывают ПК с назначенными VLAN. Пример для Switch0:")
        self.code("""vlan 10
 name VLAN10
vlan 20
 name VLAN20
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
interface range FastEthernet0/2 - 3
 switchport mode access
 switchport access vlan 20""")
        self.evidence(2, "access")
        self.table(["Соединение", "Исходный этап", "Router-on-a-stick", "Все VLAN"], [
            ["Switch0 Gi0/1 — Switch1 Gi0/1", "10, 20", "10, 20", "1, 10, 20"],
            ["Switch1 Gi0/2 — Switch2 Gi0/1", "10, 30", "10, 20, 30", "1, 10, 20, 30"],
            ["Switch2 Gi0/2 — Router0 Gi0/0", "—", "10, 20, 30", "1, 10, 20, 30"],
        ], [6, 3.4, 4.1, 3.4])
        self.p("Межкоммутаторные соединения переводятся в trunk; список разрешённых VLAN задаётся "
               "командой switchport trunk allowed vlan. Проверка конфигурации выполняется командами "
               "show vlan, show vlan brief, show running-config и show interfaces trunk.")
        self.evidence(2, "trunk")
        self.h("Изоляция VLAN")
        self.p("На первом этапе проверяются PC11 → PC21 и PC11 → PC31 внутри VLAN 10, затем "
               "PC11 → PC12 и PC11 → PC34 между разными VLAN. Без маршрутизатора между различными "
               "IP-подсетями нет пути на сетевом уровне.")
        self.evidence(2, "isolation")
        self.h("Маршрутизация между VLAN")
        self.p("Router0 Gi0/0 подключается к Switch2 Gi0/2. Для каждой VLAN создаётся подинтерфейс "
               "с инкапсуляцией 802.1Q, а его IPv4-адрес назначается шлюзом соответствующим ПК. "
               "На участке Switch1–Switch2 дополнительно разрешается VLAN 20, чтобы она достигала маршрутизатора.")
        self.table(["VLAN", "Подинтерфейс", "Инкапсуляция", "Шлюз /24"], [
            [10, "Gi0/0.10", "dot1Q 10", "192.168.14.254"],
            [20, "Gi0/0.20", "dot1Q 20", "192.168.24.254"],
            [30, "Gi0/0.30", "dot1Q 30", "192.168.34.254"],
            [1, "Gi0/0.1", "dot1Q 1 native", "192.168.0.254"],
        ], [1.3, 3.7, 4.2, 4.5])
        self.p("Для включения PC14 и PC32 в общую проверку доступности на транках разрешается "
               "VLAN 1 и создаётся её native-подинтерфейс со шлюзом 192.168.0.254. "
               "Это дополняет маршрутизацию VLAN 10, 20 и 30.")
        self.evidence(2, "routing")
        self.h("Проверка после настройки маршрутизатора")
        self.evidence(2, "checks")
        self.results(2)
        self.questions(2)

    def lab3(self):
        self.h("Лабораторная работа 3", 1, page=True)
        self.h("STP и агрегация каналов")
        self.p("Цель — изучить выбор корневого моста и ролей портов STP, настроить EtherChannel "
               "и проверить сохранение связи при отказе одного физического канала.")
        self.p("Задание — соединить три Cisco 2960 треугольником, изменить корневой коммутатор, "
               "объединить два соединения Switch0–Switch2 через LACP и исследовать "
               "циркуляцию ARP при отключённом STP в отдельном учебном стенде.")
        self.evidence(3, "topology")
        self.table(["ПК", "Подключение", "IPv4", "Маска"],
                   [[p["pc"], p["switch"] + " " + p["port"], p["ip"], p["mask"]] for p in self.data["lab3"]["pcs"]], [1.2, 4.2, 3.6, 4])
        self.p("Все ПК находятся в VLAN 1 и сети 192.168.4.0/24. Шлюз по умолчанию не требуется. "
               "Исходные соединения: Switch0 Fa0/2 — Switch2 Fa0/2, Switch0 Fa0/4 — Switch1 Fa0/4, "
               "Switch1 Fa0/5 — Switch2 Fa0/5.")
        self.h("Выбор корня и роли портов")
        self.p("Команда show spanning-tree vlan 1 показывает Root ID, Bridge ID и роли портов. "
               "При равном приоритете корень определяется по наименьшему MAC-адресу моста. "
               "Избыточный путь блокируется, чтобы активная топология не содержала канальной петли.")
        self.evidence(3, "stp_initial")
        self.p("Для переназначения корня на некорневом коммутаторе применяется "
               "spanning-tree vlan 1 root primary. После сходимости повторно проверяются Root ID, "
               "приоритет и роли портов.")
        self.evidence(3, "stp_root")
        self.h("Агрегация EtherChannel через LACP")
        self.p("К соединению Switch0–Switch2 добавляется линия Fa0/3. На обоих коммутаторах "
               "интерфейсы Fa0/2 и Fa0/3 объединяются в Port-channel1. Режим active включает LACP.")
        self.code("""configure terminal
interface range FastEthernet0/2 - 3
 channel-group 1 mode active
end
show etherchannel summary
show spanning-tree vlan 1""")
        self.evidence(3, "lacp")
        self.h("Проверка при отключении одного канала")
        self.p("Связь PC0 → PC2 проверяется командой ping 192.168.4.3. Затем на Switch0 "
               "интерфейс Fa0/3 выключается командой shutdown, а проверка повторяется. "
               "show etherchannel summary позволяет сопоставить доступность сети с составом Port-channel1.")
        self.evidence(3, "failure")
        self.h("Наблюдение широковещательной петли")
        self.p("В отдельной копии стенда на Switch0, Switch1 и Switch2 применяется "
               "no spanning-tree vlan 1. В режиме Simulation с фильтром ARP отправляется запрос "
               "от PC0 к PC1. Список событий позволяет проследить повторные пересылки "
               "широковещательного кадра по замкнутому контуру.")
        self.evidence(3, "storm")
        self.evidence(3, "checks")
        self.results(3)
        self.questions(3)

    def lab4_content(self):
        self.h("Лабораторная работа 4", 1, page=True)
        self.h("Маршрутизация и DHCP")
        self.p("Практическая работа 7 по нумерации методички. Вариант 4.")
        self.p("Цель — рассчитать подсети переменной длины, настроить статическую и динамическую "
               "адресацию, статические маршруты и обмен маршрутами по RIPv2.")
        self.p("Задание — построить три LAN по два ПК, соединить три маршрутизатора треугольником "
               "и в каждой LAN настроить статический ПК и клиент DHCP. LAN1 требует 30 адресов хостов, "
               "LAN2 — 450, LAN3 — 500. Исходный адресный блок — 192.168.0.0/16.")
        self.evidence(4, "topology")
        self.h("Расчёт подсетей и настройка интерфейсов")
        self.p("Подсети размещаются от большего блока к меньшему. Для 500 и 450 хостов "
               "нужны блоки /23 с 510 пригодными адресами; для 30 хостов достаточно /27. "
               "Первый пригодный адрес назначается шлюзу, последний — статическому ПК.")
        self.table(["LAN", "Хостов", "Подсеть", "Маска", "Шлюз Fa7/0"],
                   [[x["lan"], x["needs"], x["network"], x["mask"], x["gateway"]] for x in self.lab4["lans"]], [1, 1.6, 4.4, 4.4, 4.2])
        bounds = []
        for lan in self.lab4["lans"]:
            net = ipaddress.ip_network(lan["network"])
            bounds.append([lan["lan"], str(net.network_address + 1), str(net.broadcast_address - 1),
                           str(net.broadcast_address), net.num_addresses - 2])
        self.table(["LAN", "Первый хост", "Последний хост", "Broadcast", "Ёмкость"], bounds, [1, 4.2, 4.2, 4.2, 1.8])
        self.table(["ПК", "IPv4", "Маска", "Шлюз"],
                   [[x["pc"], x["ip"], x["mask"], x["gateway"]] for x in self.lab4["pcs"] if x["pc"] in ("PC0", "PC2", "PC4")], [1.2, 4.4, 4.4, 4.4])
        self.p("На каждом Router PT Empty используются два медных GigabitEthernet для транзита "
               "и FastEthernet7/0 для LAN. Коммутаторы подключаются к Fa7/0 маршрутизаторов через Fa0/24.")
        self.table(["Подсеть /24", "Первый конец", "Второй конец"],
                   [[x["network"], f"{x['a']} {x['a_port']}\n{x['a_ip']}", f"{x['b']} {x['b_port']}\n{x['b_ip']}"] for x in self.lab4["transit"]], [4, 6, 6])
        self.evidence(4, "interfaces")
        self.h("Динамическая адресация DHCP")
        self.p("DHCP-сервер каждой LAN работает на её маршрутизаторе. Из выдачи исключаются "
               "первый и последний пригодные адреса, занятые шлюзом и статическим ПК. "
               "PC1, PC3 и PC5 получают адрес, маску и шлюз автоматически. Пример для Router0:")
        self.code("""ip dhcp excluded-address 192.168.4.1
ip dhcp excluded-address 192.168.4.30
ip dhcp pool LAN1
 network 192.168.4.0 255.255.255.224
 default-router 192.168.4.1""")
        self.p("Последовательность DHCP состоит из Discover, Offer, Request и ACK. "
               "Проверка выполняется через ipconfig /renew и ipconfig на клиентах и "
               "show ip dhcp binding на маршрутизаторах.")
        self.evidence(4, "dhcp")
        self.h("Статическая маршрутизация")
        self.p("Для связи LAN1 ↔ LAN2 и LAN2 ↔ LAN3 задаются следующие статические маршруты. "
               "Команда ip route принимает сеть назначения, её маску и адрес следующего узла.")
        self.table(["Маршрутизатор", "Сеть назначения", "Следующий узел"], [
            ["Router0", "192.168.2.0/23", "172.16.1.2"],
            ["Router1", "192.168.4.0/27", "172.16.1.1"],
            ["Router1", "192.168.0.0/23", "172.16.2.2"],
            ["Router2", "192.168.2.0/23", "172.16.2.1"],
        ], [3.5, 5.5, 5.5])
        self.p("В show ip route статические записи помечаются S, непосредственно подключённые "
               "сети — C. Доступность проверяется "
               "между ПК соседних LAN, в частности PC1 → PC2 и PC3 → PC4.")
        self.evidence(4, "static")
        self.h("Динамическая маршрутизация RIPv2")
        self.p("RIPv2 на Router0 и Router2 обеспечивает обмен маршрутами между LAN1 и LAN3 "
               "по общему каналу GigabitEthernet8/0. Интерфейсы LAN и Gi9/0 переводятся в passive "
               "для RIP. Router1 сохраняет статическую маршрутизацию. Пример Router0:")
        self.code("""router rip
 version 2
 no auto-summary
 passive-interface FastEthernet7/0
 passive-interface GigabitEthernet9/0
 network 192.168.4.0
 network 172.16.0.0""")
        self.p("На Router2 вместо network 192.168.4.0 указывается network 192.168.0.0. "
               "Команда no auto-summary сохраняет фактические маски подсетей при передаче "
               "маршрутов через другую основную сеть. Маршруты RIP отмечаются R; в записи "
               "[120/1] число 120 — административная дистанция, 1 — метрика в переходах.")
        self.evidence(4, "rip")
        self.h("Проверка связи между локальными сетями")
        self.evidence(4, "checks")
        self.results(4)
        self.questions(4)

    def validate(self):
        labs = self.manifest.get("labs", {})
        for lab in map(str, range(1, 5)):
            record = labs.get(lab, {})
            if self.strict:
                if record.get("complete") is not True:
                    raise ValueError(f"Lab {lab}: evidence review must be marked complete")
                if not record.get("screenshots") or not record.get("conclusion"):
                    raise ValueError(f"Lab {lab}: verified screenshots and conclusion required")
                if not (record.get("observations") or record.get("slot_observations") or record.get("results")):
                    raise ValueError(f"Lab {lab}: verified observations required")
                required = set(SLOTS[lab]) - ({"checks"} if lab == "3" else set())
                covered = {item.get("slot", "checks") for item in record["screenshots"]}
                if missing := required - covered:
                    raise ValueError(f"Lab {lab}: missing screenshot stages {sorted(missing)}")
            for i, item in enumerate(record.get("screenshots", [])):
                if not item.get("caption"):
                    raise ValueError(f"Missing caption: lab {lab}, screenshot {i}")
                if item.get("slot", "checks") not in SLOTS[lab]:
                    raise ValueError(f"Unknown slot: {lab}/{item.get('slot')}")
                if (lab, i) not in self.inserted:
                    raise ValueError(f"Screenshot not inserted: {lab}/{i}")
        texts = "\n".join(p.text for p in self.doc.paragraphs)
        for forbidden in ("156", "локальной программной модели", "в модели", "требуется уточнить", "демонстрационного расчёта"):
            if forbidden in texts:
                raise ValueError(f"Obsolete model/draft text in report: {forbidden}")
        assert sum(len(v) for v in self.qa.values()) == 40

    def build(self, output):
        self.opening()
        self.lab1()
        self.lab2()
        self.lab3()
        self.lab4_content()
        self.validate()
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(output)
        print(json.dumps({"output": str(output), "questions": 40, "figures": dict(self.figures)}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=HERE / "report_manifest.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    Report(load_json(args.manifest), strict=args.strict).build(args.output)


if __name__ == "__main__":
    main()
