"""
STEP 5 - ANALISIS HASIL
=================================
Menganalisis hasil pengujian Echidna dan menghitung metrik evaluasi
sesuai proposal Bab 2.5 (Metrik Evaluasi):

  1. Detection Rate    : Jumlah bug terdeteksi / total bug disuntikkan
  2. Activation Rate   : Jumlah bug yang barisnya tercapai fuzzer / total
  3. Avg Detection Time: Rata-rata waktu deteksi per varian bug

Referensi proposal Bab 3.7 (Analisis Hasil)
"""

import os
import json
import csv
from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime

from config import (
    ANALYSIS_RESULTS_DIR,
    LOGS_DIR,
    ECHIDNA_TIMEOUT,
    BUG_VARIANTS,
)
from logger import get_logger

log = get_logger("analyzer")


# ─── Data Classes ─────────────────────────────────────────────────────────────

class MetricResult:
    """Ringkasan metrik untuk satu varian bug."""

    def __init__(self, variant: str):
        self.variant          = variant
        self.total_injected   = 0
        self.total_detected   = 0
        self.total_activated  = 0
        self.total_timeout    = 0
        self.total_error      = 0
        self.detection_times  = []   # deteksi waktu dalam detik (hanya yang DETECTED)
        self.not_detected_files: List[str] = []
        self.detected_files:    List[str] = []

    @property
    def detection_rate(self) -> float:
        """Detection Rate = Detected / Total Injected (Bab 2.5.1)"""
        if self.total_injected == 0:
            return 0.0
        return self.total_detected / self.total_injected

    @property
    def activation_rate(self) -> float:
        """Activation Rate = Activated / Total Injected (Bab 2.5.2)"""
        if self.total_injected == 0:
            return 0.0
        return self.total_activated / self.total_injected

    @property
    def avg_detection_time(self) -> float:
        """
        Rata-rata Waktu Deteksi Per Varian Bug (Bab 2.5.3)
        Jika tidak terdeteksi = nilai timeout (default)
        """
        if not self.detection_times:
            return ECHIDNA_TIMEOUT
        return sum(self.detection_times) / len(self.detection_times)

    def to_dict(self) -> dict:
        return {
            "variant":             self.variant,
            "total_injected":      self.total_injected,
            "total_detected":      self.total_detected,
            "total_not_detected":  self.total_injected - self.total_detected - self.total_timeout - self.total_error,
            "total_activated":     self.total_activated,
            "total_timeout":       self.total_timeout,
            "total_error":         self.total_error,
            "detection_rate":      round(self.detection_rate, 4),
            "detection_rate_pct":  f"{self.detection_rate * 100:.2f}%",
            "activation_rate":     round(self.activation_rate, 4),
            "activation_rate_pct": f"{self.activation_rate * 100:.2f}%",
            "avg_detection_time_sec": round(self.avg_detection_time, 2),
            "detected_files":      self.detected_files,
            "not_detected_files":  self.not_detected_files,
        }


# ─── Fungsi Analisis ──────────────────────────────────────────────────────────

def load_echidna_results(results_json_path: str) -> list:
    """Memuat hasil Echidna dari file JSON."""
    if not os.path.isfile(results_json_path):
        log.error("File hasil Echidna tidak ditemukan: %s", results_json_path)
        return []

    with open(results_json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_injection_log(injection_log_path: str) -> list:
    """Memuat injection log dari file JSON."""
    if not os.path.isfile(injection_log_path):
        log.error("Injection log tidak ditemukan: %s", injection_log_path)
        return []

    with open(injection_log_path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(echidna_results: list) -> Dict[str, MetricResult]:
    """
    Menghitung semua metrik dari hasil Echidna.

    Return:
        dict: {"single_function": MetricResult, "cross_function": MetricResult, ...}
    """
    # Inisialisasi metrik per varian
    metrics: Dict[str, MetricResult] = {}
    for variant in BUG_VARIANTS:
        metrics[variant] = MetricResult(variant)

    # Tambahkan entry "overall" untuk agregat semua varian
    metrics["overall"] = MetricResult("overall")

    for result in echidna_results:
        variant = result.get("variant", "unknown")

        # Normalisasi nama varian
        if variant not in metrics:
            metrics[variant] = MetricResult(variant)

        mr = metrics[variant]
        mr_overall = metrics["overall"]

        # Tambah counter
        mr.total_injected  += 1
        mr_overall.total_injected += 1

        status = result.get("status", "UNKNOWN")
        property_broken = result.get("property_broken", False)
        bug_line_hit    = result.get("bug_line_hit", False)
        detection_time  = result.get("detection_time_sec", -1.0)
        source_file     = result.get("source_file", "unknown")

        # ── Detection Rate ─────────────────────────────────────────────────
        if status == "DETECTED" and property_broken:
            mr.total_detected  += 1
            mr_overall.total_detected += 1
            mr.detected_files.append(source_file)
            mr_overall.detected_files.append(source_file)

            if detection_time > 0:
                mr.detection_times.append(detection_time)
                mr_overall.detection_times.append(detection_time)
        else:
            mr.not_detected_files.append(source_file)
            mr_overall.not_detected_files.append(source_file)

        # ── Activation Rate ────────────────────────────────────────────────
        if bug_line_hit:
            mr.total_activated  += 1
            mr_overall.total_activated += 1

        # ── Status lainnya ─────────────────────────────────────────────────
        if status == "TIMEOUT":
            mr.total_timeout  += 1
            mr_overall.total_timeout += 1
        elif status == "ERROR":
            mr.total_error  += 1
            mr_overall.total_error += 1

    return metrics


def print_metrics_table(metrics: Dict[str, MetricResult]) -> None:
    """Menampilkan tabel metrik ke console."""
    separator = "=" * 80
    log.info("")
    log.info(separator)
    log.info("HASIL ANALISIS - RINGKASAN METRIK")
    log.info(separator)

    # Header tabel
    header = (
        f"{'Varian':<20} | {'Total':<6} | {'Detected':<9} | "
        f"{'DR%':<8} | {'Activated':<10} | {'AR%':<8} | {'Avg Time(s)':<12}"
    )
    log.info(header)
    log.info("-" * 80)

    for variant, mr in metrics.items():
        if mr.total_injected == 0:
            continue

        dr_pct  = mr.detection_rate  * 100
        ar_pct  = mr.activation_rate * 100
        avg_t   = mr.avg_detection_time

        row = (
            f"{mr.variant:<20} | {mr.total_injected:<6} | {mr.total_detected:<9} | "
            f"{dr_pct:<7.1f}% | {mr.total_activated:<10} | {ar_pct:<7.1f}% | {avg_t:<12.2f}"
        )
        log.info(row)

    log.info(separator)


def export_to_csv(
    metrics: Dict[str, MetricResult],
    output_path: str,
) -> None:
    """Mengekspor metrik ke file CSV."""
    fieldnames = [
        "variant", "total_injected", "total_detected", "total_not_detected",
        "total_activated", "total_timeout", "total_error",
        "detection_rate", "detection_rate_pct",
        "activation_rate", "activation_rate_pct",
        "avg_detection_time_sec",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for mr in metrics.values():
            if mr.total_injected == 0:
                continue
            row = {k: mr.to_dict().get(k, "") for k in fieldnames}
            writer.writerow(row)

    log.info("Metrik CSV tersimpan di: %s", output_path)


def export_detail_csv(
    echidna_results: list,
    output_path: str,
) -> None:
    """Mengekspor hasil per kontrak ke CSV."""
    fieldnames = [
        "source_file", "contract_name", "variant",
        "status", "property_broken", "bug_line_hit",
        "detection_time_sec", "error_message",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in echidna_results:
            row = {k: result.get(k, "") for k in fieldnames}
            writer.writerow(row)

    log.info("Detail hasil CSV tersimpan di: %s", output_path)


def generate_summary_json(
    metrics: Dict[str, MetricResult],
    echidna_results: list,
    output_path: str,
) -> None:
    """Menghasilkan file ringkasan JSON lengkap."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = {
        "timestamp":       timestamp,
        "tool":            "Dynamic Reentrancy Bug Injection Tool",
        "description":     "Evaluasi efektivitas Echidna dalam mendeteksi reentrancy via bug injection",
        "reference":       "Ghaleb & Pattabiraman (2020) - SolidiFI, diadaptasi untuk analisis dinamis",
        "metrics_per_variant": {
            variant: mr.to_dict()
            for variant, mr in metrics.items()
            if mr.total_injected > 0
        },
        "raw_results": echidna_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    log.info("Ringkasan JSON tersimpan di: %s", output_path)


def run_analysis(
    echidna_results_json: str = None,
    injection_log_json: str   = None,
    output_dir: str           = ANALYSIS_RESULTS_DIR,
) -> Dict[str, MetricResult]:
    """
    Menjalankan analisis lengkap dari hasil Echidna.

    Parameter:
        echidna_results_json : path ke hasil Echidna (JSON)
        injection_log_json   : path ke injection log (JSON)
        output_dir           : direktori output analisis

    Return:
        dict metrik per varian bug
    """
    if echidna_results_json is None:
        echidna_results_json = os.path.join(LOGS_DIR, "echidna_results.json")
    if injection_log_json is None:
        injection_log_json = os.path.join(LOGS_DIR, "injection_log.json")

    os.makedirs(output_dir, exist_ok=True)

    log.info("=" * 60)
    log.info("STEP 5: ANALISIS HASIL")
    log.info("=" * 60)

    # ── Muat data ──────────────────────────────────────────────────────────────
    echidna_results = load_echidna_results(echidna_results_json)
    injection_log   = load_injection_log(injection_log_json)

    if not echidna_results:
        log.error("Tidak ada hasil Echidna untuk dianalisis.")
        return {}

    log.info("Total hasil Echidna dimuat: %d entri", len(echidna_results))

    # ── Hitung metrik ──────────────────────────────────────────────────────────
    metrics = compute_metrics(echidna_results)

    # ── Tampilkan tabel ────────────────────────────────────────────────────────
    print_metrics_table(metrics)

    # ── Ekspor hasil ───────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV metrik ringkasan
    csv_metrics_path = os.path.join(output_dir, f"metrics_summary_{timestamp}.csv")
    export_to_csv(metrics, csv_metrics_path)

    # CSV detail per kontrak
    csv_detail_path = os.path.join(output_dir, f"results_detail_{timestamp}.csv")
    export_detail_csv(echidna_results, csv_detail_path)

    # JSON ringkasan lengkap
    json_summary_path = os.path.join(output_dir, f"summary_{timestamp}.json")
    generate_summary_json(metrics, echidna_results, json_summary_path)

    # ── Tampilkan insight tambahan ─────────────────────────────────────────────
    overall = metrics.get("overall")
    if overall and overall.total_injected > 0:
        log.info("")
        log.info("INSIGHT UTAMA:")
        log.info(
            "  Detection Rate  (keseluruhan): %.2f%% (%d/%d)",
            overall.detection_rate * 100,
            overall.total_detected,
            overall.total_injected,
        )
        log.info(
            "  Activation Rate (keseluruhan): %.2f%% (%d/%d)",
            overall.activation_rate * 100,
            overall.total_activated,
            overall.total_injected,
        )
        log.info(
            "  Avg Deteksi (yang terdeteksi) : %.2f detik",
            overall.avg_detection_time,
        )

        if overall.not_detected_files:
            log.info("")
            log.info(
                "  Bug TIDAK TERDETEKSI (%d kontrak):",
                len(overall.not_detected_files),
            )
            for f in overall.not_detected_files[:10]:  # tampilkan max 10
                log.info("    - %s", f)
            if len(overall.not_detected_files) > 10:
                log.info(
                    "    ... dan %d lainnya",
                    len(overall.not_detected_files) - 10,
                )

    return metrics


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    echidna_json   = sys.argv[1] if len(sys.argv) > 1 else None
    injection_json = sys.argv[2] if len(sys.argv) > 2 else None

    metrics = run_analysis(echidna_json, injection_json)
    if not metrics:
        sys.exit(1)
    sys.exit(0)