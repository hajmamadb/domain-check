#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
بررسی وضعیت دامنه‌های .ir از طریق WHOIS رسمی ایرنیک
بدون نیاز به کتابخانه جانبی؛ مناسب Windows / Linux / macOS

اجرا:
    python check_ir_domains.py
    python check_ir_domains.py --timeout 12 --output domains_result.csv

نکته:
    فقط پاسخ معتبر WHOIS می‌تواند وضعیت را «ثبت‌شده» یا «احتمالاً آزاد» کند.
    خطا، timeout یا پاسخ مبهم به‌عنوان «نامشخص» ثبت می‌شود.
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

DOMAINS = [
    "rasanews.ir",
    "rasakhabar.ir",
    "rasatitr.ir",
    "rasadgar.ir",
    "rasadnet.ir",
    "rasadchi.ir",
    "rasadban.ir",
    "rasadino.ir",
    "rasadplus.ir",
    "rasadnama.ir",
    "titrino.ir",
    "titrak.ir",
    "titrchi.ir",
    "titrban.ir",
    "titrplus.ir",
    "titrnet.ir",
    "titrinoo.ir",
    "titryar.ir",
    "titrgram.ir",
    "titrnama.ir",
    "dabirnet.ir",
    "dabirchi.ir",
    "dabirban.ir",
    "dabirplus.ir",
    "dabirino.ir",
    "dabiryab.ir",
    "dabirnama.ir",
    "dabiryar.ir",
    "dabirgram.ir",
    "dabirak.ir",
    "khabarino.ir",
    "khabarban.ir",
    "khabarchi.ir",
    "khabaryab.ir",
    "khabarplus.ir",
    "khabarnet.ir",
    "khabargram.ir",
    "khabarinoo.ir",
    "khabarset.ir",
    "khabarbox.ir",
    "akhbarino.ir",
    "akhbaryab.ir",
    "akhbarban.ir",
    "akhbarchi.ir",
    "akhbarnet.ir",
    "akhbarplus.ir",
    "akhbarak.ir",
    "akhbarset.ir",
    "akhbarbin.ir",
    "akhbarnama.ir",
    "payeshgar.ir",
    "payeshnet.ir",
    "payeshchi.ir",
    "payeshban.ir",
    "payeshyar.ir",
    "payeshino.ir",
    "payeshplus.ir",
    "payeshnama.ir",
    "payeshak.ir",
    "payeshbox.ir",
    "didyar.ir",
    "didbanak.ir",
    "didbannet.ir",
    "didbanplus.ir",
    "didbanyar.ir",
    "didbano.ir",
    "didnama.ir",
    "didchi.ir",
    "didino.ir",
    "didset.ir",
    "negahban.ir",
    "negahyar.ir",
    "negahnet.ir",
    "negahchi.ir",
    "negahino.ir",
    "negahplus.ir",
    "negahnama.ir",
    "negahak.ir",
    "negahgram.ir",
    "negahbox.ir",
    "khabin.ir",
    "khabino.ir",
    "khabyar.ir",
    "khabnet.ir",
    "khabchi.ir",
    "khabban.ir",
    "khabnama.ir",
    "khabplus.ir",
    "khabset.ir",
    "khabbox.ir",
    "tahrirak.ir",
    "tahrirchi.ir",
    "tahrirnet.ir",
    "tahrirplus.ir",
    "tahririno.ir",
    "tahriryab.ir",
    "tahrirbox.ir",
    "tahrirgram.ir",
    "tahrirnama.ir",
    "tahrirban.ir",
]

REGISTERED_MARKERS = (
    "domain holder", "holder-c:", "admin-c:", "nserver:",
    "remarks: (domain holder)", "source: irnic"
)
AVAILABLE_MARKERS = (
    "no entries found", "no match", "not found",
    "no object found", "the queried object does not exist",
    "is available"
)

def query_whois(domain: str, timeout: float) -> str:
    with socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((domain + "\r\n").encode("ascii"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace").strip()

def classify(response: str):
    text = response.lower()
    if not text:
        return "نامشخص", "پاسخ خالی از WHOIS"

    # وجود رکورد دامنه با فیلدهای ثبت‌کننده/کارگزار
    if any(marker in text for marker in REGISTERED_MARKERS):
        return "ثبت‌شده", "رکورد دامنه در پاسخ WHOIS مشاهده شد"

    if any(marker in text for marker in AVAILABLE_MARKERS):
        return "احتمالاً آزاد", "WHOIS پیام عدم وجود رکورد برگرداند؛ در ایرنیک نهایی‌سازی شود"

    return "نامشخص", "قالب پاسخ برای تشخیص قطعی کافی نیست"

def main():
    parser = argparse.ArgumentParser(description="استعلام دامنه‌های .ir از WHOIS ایرنیک")
    parser.add_argument("--timeout", type=float, default=10, help="مهلت هر استعلام بر حسب ثانیه (پیش‌فرض: 10)")
    parser.add_argument("--output", default="domains_result.csv", help="نام فایل CSV خروجی")
    parser.add_argument("--delay", type=float, default=1.0, help="فاصله بین درخواست‌ها بر حسب ثانیه")
    args = parser.parse_args()

    results = []
    print(f"WHOIS: {WHOIS_HOST}:{WHOIS_PORT}")
    print(f"زمان شروع: {datetime.now().astimezone().isoformat(timespec='seconds')}\n")

    for index, domain in enumerate(DOMAINS, start=1):
        print(f"[{index:02}/{len(DOMAINS)}] {domain:<26}", end=" ", flush=True)
        try:
            response = query_whois(domain, args.timeout)
            status, note = classify(response)
            print(f"=> {status} | {note}")
            results.append({
                "domain": domain,
                "status": status,
                "note": note,
                "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "whois_response": re.sub(r"\s+", " ", response)[:3000],
            })
        except (socket.timeout, TimeoutError) as exc:
            note = f"Timeout: {exc}"
            print(f"=> نامشخص | {note}")
            results.append({"domain": domain, "status": "نامشخص", "note": note,
                            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                            "whois_response": ""})
        except OSError as exc:
            note = f"خطای اتصال/DNS: {exc}"
            print(f"=> نامشخص | {note}")
            results.append({"domain": domain, "status": "نامشخص", "note": note,
                            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                            "whois_response": ""})
        if index < len(DOMAINS):
            time.sleep(max(0, args.delay))

    output = Path(args.output).expanduser().resolve()
    with output.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=[
            "domain", "status", "note", "checked_at", "whois_response"
        ])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nفایل گزارش ذخیره شد: {output}")
    print("\nخلاصه:")
    for status in ("ثبت‌شده", "احتمالاً آزاد", "نامشخص"):
        count = sum(row["status"] == status for row in results)
        print(f"  {status}: {count}")

    if all(row["status"] == "نامشخص" for row in results):
        print("\nهشدار: هیچ استعلامی نتیجه قطعی نداد. اتصال شبکه/فایروال یا دسترسی به پورت 43 را بررسی کنید.")
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
