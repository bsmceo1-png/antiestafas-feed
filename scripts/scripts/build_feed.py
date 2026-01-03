import json
import re
from datetime import datetime, timezone, timedelta
from dateutil import parser as dtparser
import feedparser

KEYWORDS = {
    "SMISHING": [r"\bsms\b", r"smishing", r"texto", r"mensaje"],
    "VISHING": [r"vishing", r"llamada", r"call", r"phone"],
    "PHISHING": [r"phishing", r"suplant", r"imperson", r"credential", r"credenciales", r"iniciar sesi[oó]n", r"login"],
    "SCAM_GENERAL": [r"scam", r"fraud", r"estafa", r"fraude", r"spoof", r"impersonation"],
    "MALWARE": [r"malware", r"ransomware", r"trojan", r"botnet"],
}

def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text

def classify(title: str, summary: str) -> str:
    hay = f"{title} {summary}".lower()
    for cat, pats in KEYWORDS.items():
        for p in pats:
            if re.search(p, hay, re.IGNORECASE):
                return cat
    return "CIBERSEGURIDAD_GENERAL"

def safe_summary(entry) -> str:
    # No copiamos artículos largos: solo una síntesis corta.
    title = strip_html(getattr(entry, "title", "") or "")
    summ = strip_html(getattr(entry, "summary", "") or getattr(entry, "description", "") or "")
    # Máximo 240 chars para no “republicar” contenido.
    base = (summ[:240] + "…") if len(summ) > 240 else summ
    # Si no hay summary útil, devolvemos el título.
    return base if base else title

def parse_date(entry) -> str:
    # Prefer published/updated; fallback a "ahora"
    for field in ("published", "updated", "created"):
        val = getattr(entry, field, None)
        if val:
            try:
                dt = dtparser.parse(val)
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                pass
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def in_window(published_at_utc: str, window_hours: int) -> bool:
    try:
        dt = dtparser.parse(published_at_utc.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return dt >= (now - timedelta(hours=window_hours))
    except Exception:
        return True

def main():
    with open("sources.json", "r", encoding="utf-8") as f:
        sources = json.load(f)["sources"]

    window_hours = 6
    items = []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    for s in sources:
        feed = feedparser.parse(s["rss"])
        for e in feed.entries[:40]:
            title = strip_html(getattr(e, "title", "") or "")
            link = getattr(e, "link", "") or ""
            published_at = parse_date(e)
            summary_es = safe_summary(e)

            category = classify(title, summary_es)

            # Solo guardamos “lo reciente” para latest.json (ventana 6h).
            if not in_window(published_at, window_hours):
                continue

            item = {
                "id": re.sub(r"[^a-zA-Z0-9_\\-]+", "_", f'{s["country"]}_{s["name"]}_{published_at}_{title}')[:160],
                "published_at_utc": published_at,
                "countries": [s["country"]],
                "category": category,
                "channels": [],  # se puede inferir mejor más adelante
                "summary_es": summary_es if summary_es else title,
                "tactics": [],
                "severity": 3 if category in ("PHISHING", "SMISHING", "VISHING", "SCAM_GENERAL") else 2,
                "confidence": "MEDIA",
                "source": {"name": s["name"], "url": s["rss"]},
                "reference_url": link
            }
            items.append(item)

    # Ordena por fecha
    items.sort(key=lambda x: x["published_at_utc"], reverse=True)

    latest = {
        "generated_at_utc": now,
        "window_hours": window_hours,
        "items": items[:120]
    }

    with open("latest.json", "w", encoding="utf-8") as f:
        json.dump(latest, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
