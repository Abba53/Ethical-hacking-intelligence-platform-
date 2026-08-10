from pathlib import Path
from datetime import datetime

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)
from reportlab.lib.units import inch


class PDFGenerator:
    """
    Enterprise PDF report generator.
    """

    def __init__(self, output_dir="reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.styles = getSampleStyleSheet()

    def generate(
        self,
        *,
        target: str,
        document: str,
    ) -> str:

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        filename = (
            self.output_dir
            / f"security_report_{target.replace('/', '_').replace(':', '_')}_{timestamp}.pdf"
        )

        pdf = SimpleDocTemplate(str(filename))

        story = []

        title = Paragraph(
            "<b>Cyber Intelligence Security Assessment Report</b>",
            self.styles["Title"],
        )

        story.append(title)
        story.append(Spacer(1, 0.30 * inch))

        story.append(
            Paragraph(
                f"<b>Target:</b> {target}",
                self.styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.utcnow()} UTC",
                self.styles["Normal"],
            )
        )

        story.append(Spacer(1, 0.25 * inch))

        for line in document.splitlines():

            line = line.strip()

            if not line:
                story.append(Spacer(1, 0.12 * inch))
                continue

            story.append(
                Paragraph(
                    line.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;"),
                    self.styles["BodyText"],
                )
            )

        pdf.build(story)

        return str(filename)
