import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from  services.log_parser import cleanup_task
from  services.reports import generate_and_send_monthly_report

scheduler = AsyncIOScheduler()


def setup_report_scheduler():
    if scheduler.running:
        return
    scheduler.add_job(
        generate_and_send_monthly_report,
        "cron",
        day=1,
        hour=9,
        minute=0,
        id="monthly_report",
    )
    scheduler.start()
    print("📅 Scheduler de rapport mensuel initialisé")


def start_background_tasks():
    asyncio.create_task(cleanup_task())
    setup_report_scheduler()
