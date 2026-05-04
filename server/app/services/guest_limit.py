from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db
from app.models.tables import GuestScanDay


def utc_today():
    return datetime.now(timezone.utc).date()


def check_and_consume_guest_scan(ip: str, daily_limit: int) -> tuple[bool, int]:
    """
    Returns (allowed, current_count_after_if_allowed).
    If not allowed, current_count is the existing count (>= limit).
    """
    day = utc_today()
    row = GuestScanDay.query.filter_by(ip=ip, day=day).first()
    if row is None:
        row = GuestScanDay(ip=ip, day=day, count=1)
        db.session.add(row)
        db.session.commit()
        return True, 1
    if row.count >= daily_limit:
        return False, row.count
    row.count += 1
    db.session.commit()
    return True, row.count
