"""
report_generator.py — NPM Security Dashboard
Génère un rapport PDF mensuel à partir de la base SQLite.
Dépendances : reportlab (pip install reportlab --break-system-packages)
"""

# ── Stdlib ─────────────────────────────────────────────────────────────────────
import io
import json
import sqlite3
import contextlib
import requests
from datetime import datetime, timedelta
from pathlib import Path

# ── ReportLab ──────────────────────────────────────────────────────────────────
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics import renderPDF, shapes
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER — wraps a Drawing inside a Platypus flow
# ═══════════════════════════════════════════════════════════════════════════════
class GraphicWrapper(Flowable):
    """Intègre un Drawing ReportLab dans le flux Platypus."""

    def __init__(self, drawing: Drawing):
        Flowable.__init__(self)
        self.drawing = drawing

    def wrap(self, availWidth, availHeight):
        # Clamp la largeur pour éviter le débordement sur page étroite
        w = min(self.drawing.width, availWidth)
        return (w, self.drawing.height)

    def draw(self):
        renderPDF.draw(self.drawing, self.canv, 0, 0)


# ═══════════════════════════════════════════════════════════════════════════════
#  RAPPORT
# ═══════════════════════════════════════════════════════════════════════════════
class MonthlyReportGenerator:
    # Palette
    COLOR_PRIMARY = colors.HexColor("#3b9eff")
    COLOR_DANGER = colors.HexColor("#ff4455")
    COLOR_SUCCESS = colors.HexColor("#22d67a")
    COLOR_WARNING = colors.HexColor("#f5a623")
    COLOR_MUTED = colors.HexColor("#566a82")
    COLOR_DARK_BG = colors.HexColor("#1e2d42")
    COLOR_LIGHT_BG = colors.HexColor("#f5f8fc")

    # Couleurs par groupe de statut HTTP
    STATUS_COLORS = {
        "2xx": colors.HexColor("#22d67a"),
        "3xx": colors.HexColor("#566a82"),
        "4xx": colors.HexColor("#f5a623"),
        "444": colors.HexColor("#ff4455"),
        "429": colors.HexColor("#f5a623"),
    }

    def __init__(self, db_file: Path):
        self.db_file = db_file
        self._setup_styles()

    # ── STYLES ─────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        base = getSampleStyleSheet()
        self.style_title = ParagraphStyle(
            "Title",
            parent=base["Heading1"],
            fontSize=22,
            spaceAfter=15,
            spaceBefore=0,
            textColor=self.COLOR_PRIMARY,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            leading=26,
        )
        self.style_subtitle = ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=11,
            spaceAfter=15,
            textColor=colors.grey,
            alignment=TA_CENTER,
            leading=14,
        )
        self.style_section = ParagraphStyle(
            "Section",
            parent=base["Heading2"],
            fontSize=14,
            spaceAfter=8,
            textColor=self.COLOR_DANGER,
            fontName="Helvetica-Bold",
            leading=16,
        )
        self.style_normal = ParagraphStyle(
            "Normal",
            parent=base["Normal"],
            fontSize=9,
            leading=11,
        )
        self.style_mono = ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.darkblue,
        )
        self.style_footer = ParagraphStyle(
            "Footer",
            parent=base["Normal"],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.grey,
        )

    # ── DB ─────────────────────────────────────────────────────────────────────
    @contextlib.contextmanager
    def _db(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ── GRAPHIQUE 1 : DONUT statuts HTTP ───────────────────────────────────────
    def _create_donut_chart(self, statuses: list) -> Drawing | None:
        """Diagramme circulaire (donut) des statuts HTTP."""
        groups: dict[str, int] = {"444": 0, "429": 0, "4xx": 0, "2xx": 0, "3xx": 0}
        for s in statuses:
            code, count = s["status"], s["count"]
            if code == 444:
                groups["444"] += count
            elif code == 429:
                groups["429"] += count
            elif 200 <= code < 300:
                groups["2xx"] += count
            elif 300 <= code < 400:
                groups["3xx"] += count
            elif code >= 400:
                groups["4xx"] += count

        labels = [k for k, v in groups.items() if v > 0]
        data = [groups[k] for k in labels]
        if not data or sum(data) == 0:
            return None

        color_list = [self.STATUS_COLORS[k] for k in labels]

        DW, DH = 18 * cm, 12 * cm
        drawing = Drawing(width=DW, height=DH)

        pie = Pie()
        pie.x, pie.y = 2 * cm, 1 * cm
        pie.width = 10 * cm
        pie.height = 10 * cm
        pie.data = data
        pie.labels = labels

        # BUG CORRIGÉ : strokeColor blanc sur le slice global uniquement,
        #   ne pas l'écraser par slice (ça supprimait les séparateurs blancs)
        pie.slices.strokeWidth = 0.8
        pie.slices.strokeColor = colors.white

        for i, c in enumerate(color_list):
            pie.slices[i].fillColor = c  # couleur de remplissage
            # strokeColor intentionnellement non redéfini par slice

        drawing.add(pie)

        # ── Trou central (effet donut) ──
        cx = pie.x + pie.width / 2
        cy = pie.y + pie.height / 2
        drawing.add(
            shapes.Circle(
                cx=cx,
                cy=cy,
                r=(pie.width / 2) * 0.58,
                fillColor=colors.white,
                strokeColor=colors.white,
            )
        )

        # ── Légende à droite du disque ──
        leg_x = pie.x + pie.width + 1 * cm
        leg_y0 = pie.y + pie.height - 1 * cm
        for i, (label, c) in enumerate(zip(labels, color_list)):
            y = leg_y0 - i * 0.9 * cm
            drawing.add(
                Rect(
                    x=leg_x,
                    y=y,
                    width=0.4 * cm,
                    height=0.4 * cm,
                    fillColor=c,
                    strokeColor=c,
                )
            )
            drawing.add(
                shapes.String(
                    x=leg_x + 0.6 * cm,
                    y=y + 0.05 * cm,
                    text=f"HTTP {label}  ({groups[label]:,})",
                    fontSize=8,
                    fontName="Helvetica",
                    fillColor=colors.black,
                )
            )

        return drawing

    # ── GRAPHIQUE 2 : BARRES GROUPÉES pays (Autorisé / Bloqué) ────────────────
    def _create_bar_chart_countries(self, countries: list) -> Drawing | None:
        """Barres verticales groupées : autorisé vs bloqué par pays."""
        if not countries:
            return None

        top = countries[:10]

        # BUG CORRIGÉ : data doit être [série][catégorie], pas [catégorie][série]
        #   Série 0 = Autorisé,  Série 1 = Bloqué
        series_allowed = [int((r["total"] or 0) - (r["blocked"] or 0)) for r in top]
        series_blocked = [int(r["blocked"] or 0) for r in top]

        # BUG CORRIGÉ : categoryAxis.categoryNames pour les labels X
        category_names = [
            f"{r['country_code']}\n{str(r['country_name'] or '')[:12]}" for r in top
        ]

        DW = 17 * cm
        DH = 9 * cm
        drawing = Drawing(width=DW, height=DH)

        chart = VerticalBarChart()
        chart.x = 1.5 * cm
        chart.y = 1.5 * cm
        chart.width = DW - 2 * cm
        chart.height = DH - 2.5 * cm

        chart.data = [series_allowed, series_blocked]  # 2 séries, N catégories
        chart.categoryAxis.categoryNames = category_names

        chart.bars[0].fillColor = self.COLOR_PRIMARY  # Autorisé = bleu
        chart.bars[1].fillColor = self.COLOR_DANGER  # Bloqué   = rouge

        chart.barSpacing = 2
        chart.groupSpacing = 8

        chart.categoryAxis.labels.fontSize = 7
        chart.categoryAxis.labels.fontName = "Helvetica"
        chart.categoryAxis.labels.angle = 0

        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.labels.fontName = "Helvetica"
        chart.valueAxis.forceZero = 1

        drawing.add(chart)

        # Légende
        for i, (label, c) in enumerate(
            [("Autorisé", self.COLOR_PRIMARY), ("Bloqué", self.COLOR_DANGER)]
        ):
            lx = 1.5 * cm + i * 4 * cm
            ly = DH - 0.6 * cm
            drawing.add(
                Rect(
                    x=lx,
                    y=ly,
                    width=0.4 * cm,
                    height=0.3 * cm,
                    fillColor=c,
                    strokeColor=c,
                )
            )
            drawing.add(
                shapes.String(
                    x=lx + 0.6 * cm,
                    y=ly,
                    text=label,
                    fontSize=8,
                    fontName="Helvetica",
                    fillColor=colors.black,
                )
            )

        return drawing

    # ── GRAPHIQUE 3 : BARRES statuts HTTP (couleur par statut) ────────────────
    def _create_bar_chart_statuses(self, statuses: list) -> Drawing | None:
        """Barres verticales par code HTTP, une couleur par groupe."""
        if not statuses:
            return None

        top = statuses[:10]

        # Chaque statut = 1 série avec 1 valeur → 1 barre colorable via bars[i]
        # C'est l'approche correcte pour du per-bar coloring en ReportLab
        data = [[int(s["count"])] for s in top]
        labels = [str(s["status"]) for s in top]

        DW, DH = 17 * cm, 8 * cm
        drawing = Drawing(width=DW, height=DH)

        chart = VerticalBarChart()
        chart.x = 1 * cm
        chart.y = 1.2 * cm
        chart.width = DW - 1.5 * cm
        chart.height = DH - 2 * cm

        chart.data = data
        chart.categoryAxis.categoryNames = [""]  # une seule catégorie vide

        # BUG CORRIGÉ : bars[i] réfère à la série i (= le statut i ici)
        for i, s in enumerate(top):
            code = s["status"]
            if 200 <= code < 300:
                chart.bars[i].fillColor = self.COLOR_SUCCESS
            elif 300 <= code < 400:
                chart.bars[i].fillColor = self.COLOR_MUTED
            elif code == 444:
                chart.bars[i].fillColor = self.COLOR_DANGER
            elif code == 429:
                chart.bars[i].fillColor = self.COLOR_WARNING
            else:
                chart.bars[i].fillColor = self.COLOR_WARNING

        chart.barSpacing = 4
        chart.groupSpacing = 2

        chart.categoryAxis.labels.fontSize = 7
        chart.categoryAxis.labels.fontName = "Helvetica"
        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.labels.fontName = "Helvetica"
        chart.valueAxis.forceZero = 1

        drawing.add(chart)

        # Labels des codes HTTP sous les barres (dessinés manuellement car
        # categoryAxis n'affiche qu'une catégorie dans ce mode)
        n = len(top)
        bar_w_total = chart.width / n
        for i, label in enumerate(labels):
            bx = chart.x + i * bar_w_total + bar_w_total / 2
            drawing.add(
                shapes.String(
                    x=bx,
                    y=chart.y - 0.8 * cm,
                    text=label,
                    fontSize=7,
                    fontName="Helvetica-Bold",
                    fillColor=colors.black,
                    textAnchor="middle",
                )
            )

        return drawing

    # ── DONNÉES ────────────────────────────────────────────────────────────────
    def _get_global_stats(self, conn, start, end) -> dict:
        row = conn.execute(
            """
            SELECT COUNT(*)           AS total,
                   COALESCE(SUM(blocked), 0) AS blocked,
                   COUNT(DISTINCT ip)          AS unique_ips,
                   COUNT(DISTINCT host)        AS unique_hosts,
                   COUNT(DISTINCT country_code) AS unique_countries
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ?
        """,
            [start.isoformat(), end.isoformat()],
        ).fetchone()
        total = row["total"] or 0
        blocked = row["blocked"] or 0
        return {
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "unique_ips": row["unique_ips"] or 0,
            "unique_hosts": row["unique_hosts"] or 0,
            "unique_countries": row["unique_countries"] or 0,
            "block_rate": (blocked / total * 100) if total else 0.0,
        }

    def _get_top_hosts(self, conn, start, end, limit=20):
        return conn.execute(
            """
            SELECT host, COUNT(*) AS total, COALESCE(SUM(blocked),0) AS blocked
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ? AND host IS NOT NULL AND host != ''
            GROUP BY host ORDER BY total DESC LIMIT ?
        """,
            [start.isoformat(), end.isoformat(), limit],
        ).fetchall()

    def _get_top_attackers(self, conn, start, end, limit=20):
        return conn.execute(
            """
            SELECT ip, COUNT(*) AS total,
                   MAX(country_name) AS country,
                   MAX(isp)          AS isp,
                   MAX(timestamp)    AS last_seen
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ? AND blocked = 1
            GROUP BY ip ORDER BY total DESC LIMIT ?
        """,
            [start.isoformat(), end.isoformat(), limit],
        ).fetchall()

    def _get_top_countries(self, conn, start, end, limit=15):
        return conn.execute(
            """
            SELECT country_code, country_name,
                   COUNT(*) AS total,
                   COALESCE(SUM(blocked), 0) AS blocked
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY country_code ORDER BY total DESC LIMIT ?
        """,
            [start.isoformat(), end.isoformat(), limit],
        ).fetchall()

    def _get_status_distribution(self, conn, start, end):
        return conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY status ORDER BY count DESC
        """,
            [start.isoformat(), end.isoformat()],
        ).fetchall()

    def _get_top_uris(self, conn, start, end, limit=15):
        return conn.execute(
            """
            SELECT uri, COUNT(*) AS total, COALESCE(SUM(blocked), 0) AS blocked
            FROM access_logs
            WHERE timestamp BETWEEN ? AND ? AND uri IS NOT NULL AND uri != ''
            GROUP BY uri ORDER BY total DESC LIMIT ?
        """,
            [start.isoformat(), end.isoformat(), limit],
        ).fetchall()

    # ── TABLEAUX ───────────────────────────────────────────────────────────────
    def _table_style(self, header_color, zebra=True) -> TableStyle:
        cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#263447")),
        ]
        if zebra:
            cmds.append(
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, self.COLOR_LIGHT_BG],
                )
            )
        return TableStyle(cmds)

    def _create_summary_table(self, stats: dict) -> Table:
        data = [
            ["Métrique", "Valeur"],
            ["Total requêtes", f"{stats['total']:,}"],
            [
                "Requêtes bloquées",
                f"{stats['blocked']:,}  ({stats['block_rate']:.1f} %)",
            ],
            ["Requêtes autorisées", f"{stats['allowed']:,}"],
            ["IPs uniques", f"{stats['unique_ips']:,}"],
            ["Hosts uniques", f"{stats['unique_hosts']:,}"],
            ["Pays uniques", f"{stats['unique_countries']:,}"],
        ]
        t = Table(data, colWidths=[7 * cm, 6 * cm])
        t.setStyle(self._table_style(self.COLOR_PRIMARY))
        return t

    def _create_status_table(self, statuses) -> Table:
        total = sum(s["count"] for s in statuses) or 1
        data = [["Status HTTP", "Nombre", "%"]]
        for s in statuses:
            data.append(
                [str(s["status"]), f"{s['count']:,}", f"{s['count']/total*100:.1f} %"]
            )
        t = Table(data, colWidths=[3 * cm, 4 * cm, 2.5 * cm])
        t.setStyle(self._table_style(self.COLOR_DARK_BG))
        return t

    def _create_hosts_table(self, hosts) -> Table:
        data = [["Host", "Total", "Bloquées", "% Blocage"]]
        for h in hosts:
            pct = (h["blocked"] / max(h["total"], 1)) * 100
            data.append(
                [
                    Paragraph(str(h["host"])[:45], self.style_mono),
                    f"{h['total']:,}",
                    f"{h['blocked']:,}",
                    f"{pct:.1f} %",
                ]
            )
        t = Table(data, colWidths=[7 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
        t.setStyle(self._table_style(self.COLOR_DARK_BG))
        return t

    def _create_attackers_table(self, attackers) -> Table:
        data = [["IP", "Attaques", "Pays", "ISP", "Dernière"]]
        for a in attackers:
            last = (
                datetime.fromisoformat(a["last_seen"]).strftime("%d/%m %H:%M")
                if a["last_seen"]
                else "—"
            )
            data.append(
                [
                    Paragraph(str(a["ip"]), self.style_mono),
                    f"{a['total']:,}",
                    str(a["country"] or "")[:15],
                    str(a["isp"] or "")[:22],
                    last,
                ]
            )
        t = Table(data, colWidths=[3.5 * cm, 2 * cm, 3 * cm, 4 * cm, 2.5 * cm])
        t.setStyle(self._table_style(self.COLOR_DANGER))
        return t

    def _create_countries_table(self, countries) -> Table:
        data = [["Pays", "Code", "Total", "Bloquées", "% Blocage"]]
        for c in countries:
            pct = (c["blocked"] / max(c["total"], 1)) * 100
            data.append(
                [
                    str(c["country_name"] or "")[:22],
                    str(c["country_code"] or ""),
                    f"{c['total']:,}",
                    f"{c['blocked']:,}",
                    f"{pct:.1f} %",
                ]
            )
        t = Table(data, colWidths=[4.5 * cm, 2 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
        t.setStyle(self._table_style(self.COLOR_DARK_BG))
        return t

    def _create_uris_table(self, uris) -> Table:
        data = [["URI", "Total", "Bloquées"]]
        for u in uris:
            data.append(
                [
                    Paragraph(str(u["uri"] or "")[:55], self.style_mono),
                    f"{u['total']:,}",
                    f"{u['blocked']:,}",
                ]
            )
        t = Table(data, colWidths=[9.5 * cm, 2.5 * cm, 2.5 * cm])
        t.setStyle(self._table_style(self.COLOR_DARK_BG))
        return t

    # ── GÉNÉRATION DU PDF ──────────────────────────────────────────────────────
    def generate_report(self, period_days: int = 30) -> bytes:
        """Génère le rapport PDF et retourne les bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        elements = []
        end = datetime.now()
        start = end - timedelta(days=period_days)

        # ── En-tête ──
        elements += [
            Paragraph("NPM Security", self.style_title),
            Paragraph("Rapport Mensuel d'Analyse de Sécurité", self.style_subtitle),
            Spacer(1, 0.4 * cm),
            Paragraph(
                f"Période : {start.strftime('%d/%m/%Y')} → {end.strftime('%d/%m/%Y')}",
                self.style_normal,
            ),
            Spacer(1, 0.8 * cm),
        ]

        # ── Résumé global ──
        elements.append(Paragraph("📊 Résumé Global", self.style_section))
        with self._db() as conn:
            stats = self._get_global_stats(conn, start, end)
        elements += [self._create_summary_table(stats), PageBreak()]

        # ── Statuts HTTP (donut + barres + tableau) ──
        elements.append(
            Paragraph("📈 Distribution des Statuts HTTP", self.style_section)
        )
        with self._db() as conn:
            statuses = self._get_status_distribution(conn, start, end)

        donut = self._create_donut_chart(statuses)
        elements.append(
            GraphicWrapper(donut)
            if donut
            else Paragraph("Aucune donnée", self.style_normal)
        )
        elements.append(Spacer(1, 0.3 * cm))

        bars_status = self._create_bar_chart_statuses(statuses)
        elements.append(GraphicWrapper(bars_status) if bars_status else Spacer(1, 0))
        elements.append(Spacer(1, 0.4 * cm))
        elements += [self._create_status_table(statuses), PageBreak()]

        # ── Top hosts ──
        elements.append(Paragraph("🌐 Top Hosts", self.style_section))
        with self._db() as conn:
            hosts = self._get_top_hosts(conn, start, end)
        elements += [self._create_hosts_table(hosts), PageBreak()]

        # ── Top IPs attaquantes ──
        elements.append(Paragraph("🎯 Top IPs Attaquantes", self.style_section))
        with self._db() as conn:
            attackers = self._get_top_attackers(conn, start, end)
        elements += [self._create_attackers_table(attackers), PageBreak()]

        # ── Répartition géographique ──
        elements.append(Paragraph("🌍 Répartition Géographique", self.style_section))
        with self._db() as conn:
            countries = self._get_top_countries(conn, start, end)

        bar_countries = self._create_bar_chart_countries(countries)
        elements.append(
            GraphicWrapper(bar_countries)
            if bar_countries
            else Paragraph("Aucune donnée", self.style_normal)
        )
        elements.append(Spacer(1, 0.4 * cm))
        elements += [self._create_countries_table(countries), PageBreak()]

        # ── Top URIs ──
        elements.append(Paragraph("🔒 Top URIs Ciblés", self.style_section))
        with self._db() as conn:
            uris = self._get_top_uris(conn, start, end)
        elements.append(self._create_uris_table(uris))

        # ── Pied de page ──
        elements += [
            Spacer(1, 1.2 * cm),
            Paragraph(
                f"Rapport généré le {end.strftime('%d/%m/%Y à %H:%M:%S')}",
                self.style_footer,
            ),
            Paragraph("NPM Security Dashboard", self.style_footer),
        ]

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
#  DISCORD — envoi du PDF via webhook (stdlib uniquement, cohérent avec main.py)
# ═══════════════════════════════════════════════════════════════════════════════
def send_discord_with_attachment(webhook_url: str, pdf_bytes: bytes, stats: dict):
    """Envoie le PDF sur Discord avec un message récapitulatif en utilisant requests"""
    if not webhook_url:
        print("⚠️ No Discord webhook configured")
        return False

    try:
        # Préparer le payload JSON
        payload = {
            "content": f"**📊 Rapport Mensuel NPM Security**\n\n"
            f"📅 Période : 30 derniers jours\n"
            f"🔢 **{stats['total']:,}** requêtes analysées\n"
            f"🚫 **{stats['blocked']:,}** bloquées ({stats['block_rate']:.1f}%)\n"
            f"🌍 **{stats['unique_countries']}** pays\n"
            f"🎯 **{stats['unique_ips']:,}** IPs uniques\n\n"
            f"📎 Voir le rapport PDF ci-joint.",
            "username": "NPM Security Reports",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/1000/1000069.png",  # Optionnel : une icône de bouclier
        }

        # Préparer les fichiers
        files = {
            "file": (
                f"rapport_npm_security_{datetime.now().strftime('%Y%m')}.pdf",
                pdf_bytes,
                "application/pdf",
            )
        }

        # Envoi avec requests (gère automatiquement les bordures multipart)
        response = requests.post(webhook_url, data=payload, files=files, timeout=30)

        if response.status_code == 204 or response.status_code == 200:
            print("✅ Rapport envoyé sur Discord")
            return True
        else:
            # Affiche l'erreur détaillée de Discord pour déboguer
            print(f"❌ Discord Error {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Discord webhook error: {e}")
        return False
