# Takes the audit results and fills the HTML template used for the final report.

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_report(data, findings, output_path, template_dir="templates"):
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )

    template = env.get_template("report.html")
    counts = Counter(item["severity"] for item in findings)

    html = template.render(
        generated_at=data.get("generated_at", "unknown"),
        findings=findings,
        counts=counts,
        total_findings=len(findings),
        user_count=len(data.get("users", [])),
        group_count=len(data.get("groups", [])),
    )

    output_file.write_text(html, encoding="utf-8")
