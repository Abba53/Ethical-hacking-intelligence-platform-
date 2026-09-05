"""
api/routers/reports.py

Phase 12 — REPORT stage: PDF generation endpoint.

Thin wrapper around the REAL reports.pdf_generator.PDFGenerator —
confirmed by reading that file directly. Does NOT reimplement PDF
layout/formatting logic.

KNOWN GAP, flagged not silently fixed: PDFGenerator.generate() escapes
&/</> in the document body, but NOT in the `target` string used in its
own "<b>Target:</b> {target}" line. Since `target` here often comes from
real IOC values (which occasionally contain unusual characters), this
router defensively strips angle brackets from `target` BEFORE passing it
to PDFGenerator — a minimal, API-layer-only safeguard that does not
modify the existing reports/pdf_generator.py file itself.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from reports.pdf_generator import PDFGenerator
from api.schemas.report import PDFReportRequest
from api.security import require_api_key

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["reports"],
    dependencies=[Depends(require_api_key)],
)


def _generate_pdf(target: str, document: str) -> str:
    """Plain, SYNCHRONOUS function — PDFGenerator.generate() does real blocking disk I/O."""
    generator = PDFGenerator()
    return generator.generate(target=target, document=document)


@router.post("/pdf")
async def generate_pdf_report(payload: PDFReportRequest):
    """
    Generates a real PDF via the existing PDFGenerator and returns it
    as a downloadable file — not JSON, since a PDF is binary content.
    """
    # Defensive, API-layer-only sanitization — see module docstring.
    # PDFGenerator itself is untouched; this only affects what THIS
    # endpoint passes into it.
    safe_target = payload.target.replace("<", "").replace(">", "")

    file_path_str = await run_in_threadpool(_generate_pdf, safe_target, payload.document)
    file_path = Path(file_path_str)

    if not file_path.exists():
        # Defensive check — PDFGenerator.build() could theoretically
        # raise inside the threadpool and still return a path in a future
        # version; better a clear 500 than silently returning a broken link.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation reported success but the file was not found.",
        )

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=file_path.name,
    )
