import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from  services.log_parser import cleanup_task
from services.ingestion import ingest_forever
from services.expiration import expire_block_rules
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
    scheduler.add_job(
        expire_block_rules,
        "interval",
        minutes=1,
        id="expire_block_rules",
        max_instances=1,
    )
    scheduler.start()
    print("📅 Scheduler de rapports et expiration des règles initialisé")


def start_background_tasks():
    expire_block_rules()
    asyncio.create_task(cleanup_task())
    asyncio.create_task(ingest_forever())
    setup_report_scheduler()
