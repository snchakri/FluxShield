import csv
import json
import urllib.parse
import urllib.request

DATASET = "notesbymuneeb/ai-waf-dataset"
CONFIG = "default"
SPLIT = "train"
ROWS_URL = "https://datasets-server.huggingface.co/rows"
SPLITS_URL = "https://datasets-server.huggingface.co/splits"
PAGE_SIZE = 100


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def build_rows_url(offset: int, length: int) -> str:
    query = {
        "dataset": DATASET,
        "config": CONFIG,
        "split": SPLIT,
        "offset": str(offset),
        "length": str(length),
    }
    return f"{ROWS_URL}?{urllib.parse.urlencode(query)}"


def build_splits_url() -> str:
    query = {"dataset": DATASET}
    return f"{SPLITS_URL}?{urllib.parse.urlencode(query)}"


def fetch_all_rows() -> list[dict]:
    first_page = fetch_json(build_rows_url(0, PAGE_SIZE))
    total = int(first_page.get("num_rows_total", 0))
    per_page = int(first_page.get("num_rows_per_page", PAGE_SIZE))

    rows = [entry["row"] for entry in first_page.get("rows", [])]

    offset = per_page
    while offset < total:
        page = fetch_json(build_rows_url(offset, per_page))
        rows.extend(entry["row"] for entry in page.get("rows", []))
        offset += per_page

    return rows


def write_rows_csv(rows: list[dict], output_path: str) -> None:
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_splits_csv(output_path: str) -> None:
    data = fetch_json(build_splits_url())
    splits = data.get("splits", [])
    fieldnames = sorted({key for entry in splits for key in entry.keys()})
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(splits)


def main() -> None:
    rows = fetch_all_rows()
    write_rows_csv(rows, "huggingface_full.csv")
    write_splits_csv("huggingface_split.csv")


if __name__ == "__main__":
    main()
