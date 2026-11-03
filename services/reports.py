from datetime import datetime, timedelta
from pathlib import Path

from  config import DB_FILE, DISCORD_WEBHOOK_URL
from  database import get_db
from  report_generator import MonthlyReportGenerator, send_discord_with_attachment

REPORT_GENERATOR = MonthlyReportGenerator(DB_FILE)
LAST_REPORT_DATE = None


def generate_and_send_monthly_report():
    """Génère et envoie le rapport mensuel"""
    global LAST_REPORT_DATE

    today = datetime.now()
    # Ne génère qu'une fois par mois (jour 1)
    if today.day != 1 or (LAST_REPORT_DATE and LAST_REPORT_DATE.month == today.month):
        return

    print("📊 Génération du rapport mensuel...")

    try:
        # Générer le PDF
        pdf_bytes = REPORT_GENERATOR.generate_report(period_days=30)

        # Obtenir les stats pour le message Discord
        with get_db() as conn:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            cursor = conn.execute(
                """
                SELECT 
                    COUNT(*) as total,
                    SUM(blocked) as blocked,
                    COUNT(DISTINCT ip) as unique_ips,
                    COUNT(DISTINCT country_code) as unique_countries
                FROM access_logs
                WHERE timestamp BETWEEN ? AND ?
            """,
                [start_date.isoformat(), end_date.isoformat()],
            )
            stats = cursor.fetchone()

            stats_dict = {
                "total": stats["total"] or 0,
                "blocked": stats["blocked"] or 0,
                "unique_ips": stats["unique_ips"] or 0,
                "unique_countries": stats["unique_countries"] or 0,
                "block_rate": ((stats["blocked"] or 0) / max(stats["total"] or 1, 1))
                * 100,
            }

        # Envoyer sur Discord
        success = send_discord_with_attachment(
            DISCORD_WEBHOOK_URL, pdf_bytes, stats_dict
        )

        if success:
            LAST_REPORT_DATE = today
            print("✅ Rapport mensuel envoyé avec succès")
        else:
            print("❌ Échec de l'envoi du rapport")

    except Exception as e:
        print(f"❌ Erreur génération rapport: {e}")


def generate_report_file(period_days: int = 30) -> tuple[bytes, dict, Path]:
    pdf_bytes = REPORT_GENERATOR.generate_report(period_days=period_days)
    report_path = Path(f"./reports/rapport_npm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_bytes(pdf_bytes)
    with get_db() as conn:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        stats = conn.execute(
            """
            SELECT COUNT(*) as total, SUM(blocked) as blocked,
                   COUNT(DISTINCT ip) as unique_ips
            FROM access_logs WHERE timestamp BETWEEN ? AND ?
            """,
            [start_date.isoformat(), end_date.isoformat()],
        ).fetchone()
        stats_dict = {
            "total": stats["total"] or 0,
            "blocked": stats["blocked"] or 0,
            "unique_ips": stats["unique_ips"] or 0,
            "unique_countries": 0,
            "block_rate": ((stats["blocked"] or 0) / max(stats["total"] or 1, 1)) * 100,
        }
    return pdf_bytes, stats_dict, report_path
