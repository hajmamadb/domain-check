#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
تولید خودکار نام دامنه‌های .ir و بررسی وضعیت آن‌ها از WHOIS ایرنیک

این برنامه:
1) نام‌های پیشنهادی مرتبط با خبر، رصد و تحریریه می‌سازد.
2) دامنه‌های تکراری و نامعتبر را حذف می‌کند.
3) از WHOIS رسمی ایرنیک (TCP/43) استعلام می‌گیرد.
4) دامنه‌های «احتمالاً آزاد» و «نامشخص» را در CSV ذخیره می‌کند.
5) نتیجه را بعد از هر دامنه در CSV می‌نویسد تا با قطع برنامه، داده‌های قبلی از بین نرود.

اجرا:
    python ir_domain_finder.py

گزینه‌ها:
    python ir_domain_finder.py --limit 1000 --timeout 10 --delay 1
    python ir_domain_finder.py --output candidates.csv --include-unknown
    python ir_domain_finder.py --all-results

مهم:
- این برنامه دامنه را ثبت/خریداری نمی‌کند؛ فقط وضعیت WHOIS را بررسی و گزارش می‌کند.
- «احتمالاً آزاد» تضمین ثبت‌پذیری نیست. قبل از خرید، در ایرنیک بررسی نهایی کنید.
- اگر دسترسی شبکه به whois.nic.ir یا پورت 43 بسته باشد، نتیجه «خطای استعلام» ثبت می‌شود.
"""

import argparse
import csv
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

WHOIS_HOST = "whois.nic.ir"
WHOIS_PORT = 43

# ریشه‌های نام مرتبط با محصول رسانه‌ای/تحریریه
ROOTS = [
    "rasad", "titr", "dabir", "tahrir", "khabar", "akhbar",
    "didban", "negah", "payesh", "baztab", "nabz", "rasa",
    "agah", "bina", "nama", "khabin", "akhbarbin", "khabaryab",
    "titrbin", "newsroom", "media", "resaneh", "khabarnegar",
    "sarparast", "sardabir", "khabarname", "tahlil", "pishkhan",
]

# پسوندها/پیشوندهای کوتاه برای ساخت نام‌های ترکیبی
SUFFIXES = [
    "yar", "bin", "ban", "jo", "chi", "gar", "ino", "inoo",
    "net", "plus", "nama", "set", "box", "hub", "gram",
    "yar", "no", "novin", "360", "ak", "an", "estan",
]
PREFIXES = ["no", "ham", "hoosh", "fara", "hamra", " abr"]

# ترکیب‌های معنایی منتخب؛ این‌ها مستقل از ترکیب خودکارند.
CURATED = [
    "rasadgar", "rasadyar", "rasadbin", "rasadban", "rasadchi",
    "titrbin", "titryar", "titrgar", "titrnama", "titrino",
    "dabiryab", "dabiry ar", "dabirbin", "dabirban", "dabirchi",
    "tahriryab", "tahriryar", "tahrirbin", "tahrirchi",
    "khabaryab", "khabarbin", "khabarban", "khabarjo",
    "akhbaryab", "akhbarbin", "akhbarban", "akhbarjo",
    "didbanyar", "didbanbin", "negahban", "negahyar",
    "payeshgar", "payeshyar", "payeshbin", "payeshban",
    "baztabyar", "nabzyar", "nabzbin", "khabarino",
    "titrplus", "dabirplus", "rasadplus", "payeshplus",
]

def normalize_name(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9-]", "", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value

def generate_domains():
    """نام‌های یکتا تولید می‌کند؛ ترتیب خروجی برای اولویت نام‌های منتخب حفظ می‌شود."""
    names = []
    seen = set()

    def add(name):
        name = normalize_name(name)
        if not name or len(name) < 3 or len(name) > 63:
            return
        if name.startswith("-") or name.endswith("-") or "--" in name:
            return
        domain = name + ".ir"
        if domain not in seen:
            seen.add(domain)
            names.append(domain)

    for name in CURATED:
        add(name)

    for root in ROOTS:
        add(root)
        for suffix in SUFFIXES:
            add(root + suffix)
        for prefix in PREFIXES:
            add(prefix + root)

    # ترکیب ریشه‌های کوتاه با یکدیگر؛ نام‌های بیش از حد بلند حذف می‌شوند.
    short_roots = [
        "rasad", "titr", "dabir", "tahrir", "khabar",
        "akhbar", "did", "negah", "payesh", "nabz",
        "rasa", "agah", "bina", "nama", "khabin",
    ]
    for first in short_roots:
        for second in short_roots:
            if first != second:
                add(first + second)

    return names

def query_whois(domain: str, timeout: float) -> str:
    with socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((domain + "\r\n").encode("ascii"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                # اگر پاسخ دریافت شده باشد، از timeout خواندن به‌عنوان پایان پاسخ استفاده می‌کنیم.
                if chunks:
                    break
                raise
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace").strip()

def classify_whois(response: str, domain: str):
    text = response.lower()
    if not text:
        return "نامشخص", "پاسخ خالی از WHOIS"

    # پیام‌های متداول عدم وجود رکورد در WHOIS
    free_markers = [
        "no entries found",
        "no match for",
        "not found in the registry",
        "no object found",
        "the queried object does not exist",
        "domain is available",
        "no data found",
    ]
    if any(marker in text for marker in free_markers):
        return "احتمالاً آزاد", "WHOIS پیام عدم وجود رکورد برگرداند"

    # وجود فیلدهای مشخص رکورد دامنه نشانه ثبت بودن است.
    registered_patterns = [
        r"(?m)^\s*domain\s+name\s*:",
        r"(?m)^\s*holder(?:-c)?\s*:",
        r"(?m)^\s*admin-c\s*:",
        r"(?m)^\s*nserver\s*:",
        r"(?m)^\s*source\s*:\s*irnic",
    ]
    if any(re.search(pattern, text) for pattern in registered_patterns):
        return "ثبت‌شده", "فیلدهای رکورد دامنه در WHOIS مشاهده شد"

    # اگر خود دامنه در پاسخ آمده ولی قالب پاسخ قابل تشخیص نیست، نتیجه را قطعی نمی‌کنیم.
    if domain.lower() in text:
        return "نامشخص", "نام دامنه در پاسخ هست، اما قالب رکورد قابل تشخیص نیست"

    return "نامشخص", "پاسخ WHOIS با الگوهای شناخته‌شده تطبیق نداشت"

def load_existing(output_path: Path):
    done = set()
    if output_path.exists():
        try:
            with output_path.open("r", newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    if row.get("domain"):
                        done.add(row["domain"].strip().lower())
        except (OSError, csv.Error):
            pass
    return done

def main():
    parser = argparse.ArgumentParser(
        description="تولید خودکار دامنه‌های .ir و بررسی WHOIS ایرنیک"
    )
    parser.add_argument("--limit", type=int, default=500,
                        help="حداکثر تعداد دامنه برای بررسی (پیش‌فرض: 500)")
    parser.add_argument("--timeout", type=float, default=10,
                        help="مهلت اتصال/دریافت پاسخ بر حسب ثانیه")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="فاصله بین استعلام‌ها بر حسب ثانیه؛ برای رعایت نرخ درخواست")
    parser.add_argument("--output", default="ir_domain_candidates.csv",
                        help="مسیر فایل CSV خروجی")
    parser.add_argument("--include-unknown", action="store_true",
                        help="علاوه بر موارد احتمالاً آزاد، موارد نامشخص را هم ذخیره کند")
    parser.add_argument("--all-results", action="store_true",
                        help="همه نتایج، از جمله دامنه‌های ثبت‌شده، در CSV ذخیره شوند")
    parser.add_argument("--retry-errors", action="store_true",
                        help="دامنه‌هایی که قبلاً خطای استعلام داشته‌اند دوباره بررسی شوند")
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit باید حداقل 1 باشد")

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    existing = load_existing(output_path)
    candidates = generate_domains()
    to_check = []
    for domain in candidates:
        if domain in existing:
            if not args.retry_errors:
                continue
        to_check.append(domain)
        if len(to_check) >= args.limit:
            break

    if not to_check:
        print("دامنه جدیدی برای بررسی باقی نمانده است.")
        print(f"فایل موجود: {output_path}")
        return 0

    file_exists = output_path.exists() and output_path.stat().st_size > 0
    fields = ["domain", "status", "note", "checked_at", "whois_response"]

    print(f"WHOIS server: {WHOIS_HOST}:{WHOIS_PORT}")
    print(f"تعداد نام‌های تولیدشده: {len(candidates)}")
    print(f"تعداد استعلام در این اجرا: {len(to_check)}")
    print(f"فایل خروجی: {output_path}\n")

    counts = {"ثبت‌شده": 0, "احتمالاً آزاد": 0, "نامشخص": 0, "خطای استعلام": 0}

    with output_path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
            f.flush()

        for index, domain in enumerate(to_check, start=1):
            print(f"[{index}/{len(to_check)}] {domain:<28}", end=" ", flush=True)
            try:
                response = query_whois(domain, args.timeout)
                status, note = classify_whois(response, domain)
            except (socket.timeout, TimeoutError) as exc:
                response = ""
                status, note = "خطای استعلام", f"Timeout: {exc}"
            except OSError as exc:
                response = ""
                status, note = "خطای استعلام", f"خطای اتصال/DNS: {exc}"

            counts[status] = counts.get(status, 0) + 1
            print(f"=> {status} | {note}")

            should_save = (
                args.all_results
                or status == "احتمالاً آزاد"
                or (args.include_unknown and status == "نامشخص")
                or status == "خطای استعلام"
            )
            if should_save:
                writer.writerow({
                    "domain": domain,
                    "status": status,
                    "note": note,
                    "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                    "whois_response": re.sub(r"\s+", " ", response)[:2500],
                })
                f.flush()

            if index < len(to_check):
                time.sleep(max(0, args.delay))

    print("\nخلاصه همین اجرا:")
    for status, count in counts.items():
        print(f"  {status}: {count}")
    print(f"\nگزارش ذخیره شد: {output_path}")
    print("توجه: فقط «احتمالاً آزاد»ها در حالت پیش‌فرض ذخیره می‌شوند؛ خطاهای استعلام نیز برای عیب‌یابی ثبت می‌شوند.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
