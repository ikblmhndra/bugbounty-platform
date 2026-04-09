from app.models.models import ScanStageType


STAGE_ORDER = [
    ScanStageType.RECON,
    ScanStageType.ENUMERATION,
    ScanStageType.PROBING,
    ScanStageType.SCANNING,
    ScanStageType.VALIDATION,
    ScanStageType.REPORTING,
]


class InvalidTransition(Exception):
    pass


def next_stage(current: ScanStageType | None) -> ScanStageType | None:
    if current is None:
        return STAGE_ORDER[0]
    try:
        idx = STAGE_ORDER.index(current)
    except ValueError as exc:
        raise InvalidTransition(f"Unknown stage: {current}") from exc
    if idx + 1 >= len(STAGE_ORDER):
        return None
    return STAGE_ORDER[idx + 1]


def is_valid_transition(current: ScanStageType | None, nxt: ScanStageType) -> bool:
    expected = next_stage(current)
    return expected == nxt
