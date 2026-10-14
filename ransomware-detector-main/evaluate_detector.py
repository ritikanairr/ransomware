"""
Safe synthetic evaluation for ransomware_detector_enhanced.py.

This does NOT encrypt files or run ransomware. It creates synthetic byte samples in a
temporary folder and measures the detector's analysis signals. Latency is function-level
analysis time, not end-to-end Watchdog event-to-alert latency.
"""
import base64
import csv
import os
import random
import tempfile
import time

import ransomware_detector_enhanced as detector


def synthetic_bytes(length=4096, seed=42):
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(length))


def write_sample(folder, name, data):
    path = os.path.join(folder, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def score_case(name, path, old_data, new_data, old_category, expected_positive):
    start = time.perf_counter()

    category = detector.get_file_category(path, new_data[:16])
    old_entropy = detector.file_entropy(old_data[:detector.WINDOW_SIZE * 4])
    entropy = detector.file_entropy(new_data[:detector.WINDOW_SIZE * 4])
    ascii_val = detector.ascii_ratio(new_data[:detector.WINDOW_SIZE * 4])
    similarity = detector.fuzzy_similarity(
        old_data[:detector.WINDOW_SIZE * 4],
        new_data[:detector.WINDOW_SIZE * 4],
    )
    was_base64 = detector.is_base64_like(old_data[:detector.WINDOW_SIZE * 4])
    now_base64 = detector.is_base64_like(new_data[:detector.WINDOW_SIZE * 4])

    entropy_alert = detector.format_entropy_suspicious(category, entropy, old_entropy)
    ascii_alert = category == "text" and ascii_val < detector.LOW_ASCII_RATIO
    similarity_alert = category == "text" and similarity < detector.SIMILARITY_THRESHOLD
    base64_transition_alert = now_base64 and not was_base64
    format_alert = category.startswith("invalid_") or (
        old_category is not None and old_category != category
    )

    detected = any((
        entropy_alert, ascii_alert, similarity_alert,
        base64_transition_alert, format_alert
    ))
    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "case": name,
        "category": category,
        "expected_positive": expected_positive,
        "detected": detected,
        "entropy_bits_per_byte": round(entropy, 4),
        "ascii_ratio": round(ascii_val, 4),
        "similarity_percent": similarity,
        "entropy_alert": entropy_alert,
        "ascii_alert": ascii_alert,
        "similarity_alert": similarity_alert,
        "base64_transition_alert": base64_transition_alert,
        "format_alert": format_alert,
        "analysis_latency_ms": round(elapsed_ms, 3),
        "false_positive": (not expected_positive and detected),
        "missed_positive": (expected_positive and not detected),
    }


def main():
    rows = []
    payload = synthetic_bytes(4096, seed=2026)
    base64_payload = base64.b64encode(payload)
    normal_before = (
        b"Project notes: this is a harmless baseline text file. "
        b"We are testing the detector using normal text edits.\n"
    )
    normal_after = normal_before.replace(b"normal text edits", b"ordinary text edits")

    # Signatures plus synthetic data are fixtures, not valid real-world documents.
    format_fixtures = {
        "sample.pdf": b"%PDF-1.7\n" + synthetic_bytes(4096, seed=1),
        "sample.docx": b"PK\x03\x04" + synthetic_bytes(4096, seed=2),
        "sample.jpg": b"\xff\xd8\xff" + synthetic_bytes(4096, seed=3),
    }

    with tempfile.TemporaryDirectory(prefix="ransomware_eval_") as folder:
        cases = []

        path = write_sample(folder, "normal.txt", normal_after)
        cases.append(("normal_text_edit", path, normal_before, normal_after, "text", False))

        # Start from ordinary text and replace it with synthetic raw bytes.
        raw_path = write_sample(folder, "raw_mode.txt", payload)
        cases.append(("raw_ciphertext_like_bytes", raw_path, normal_before, payload, "text", True))

        # Start from ordinary text and replace it with Base64 representation.
        b64_path = write_sample(folder, "base64_mode.txt", base64_payload)
        cases.append(("base64_encoded_ciphertext_like_bytes", b64_path, normal_before, base64_payload, "text", True))

        # Exercise file-type-specific entropy handling with synthetic signature fixtures.
        for filename, data in format_fixtures.items():
            category = detector.get_file_category(os.path.join(folder, filename), data[:16])
            path = write_sample(folder, filename, data)
            changed = data[:16] + synthetic_bytes(4096, seed=99)
            cases.append((f"format_change_{category}", path, data, changed, category, False))

        for args in cases:
            rows.append(score_case(*args))

    csv_path = os.path.abspath("ransomware_eval_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    positives = [r for r in rows if r["expected_positive"]]
    negatives = [r for r in rows if not r["expected_positive"]]
    tp = sum(r["detected"] for r in positives)
    fp = sum(r["false_positive"] for r in negatives)
    fn = sum(r["missed_positive"] for r in positives)
    detection_rate = tp / len(positives) if positives else 0.0
    false_positive_rate = fp / len(negatives) if negatives else 0.0

    print("\nSynthetic evaluation results (not a real-world effectiveness claim)")
    print("-" * 100)
    print(f"{'Case':42} {'Entropy':>8} {'B64':>5} {'Detected':>9} {'Latency ms':>11}")
    for row in rows:
        print(
            f"{row['case'][:42]:42} "
            f"{row['entropy_bits_per_byte']:8.3f} "
            f"{str(row['base64_transition_alert']):>5} "
            f"{str(row['detected']):>9} "
            f"{row['analysis_latency_ms']:11.3f}"
        )
    print("-" * 100)
    print(f"Detection rate:       {detection_rate:.1%} ({tp}/{len(positives)} positive cases)")
    print(f"False-positive rate:  {false_positive_rate:.1%} ({fp}/{len(negatives)} clean cases)")
    print(f"Missed positives:     {fn}")
    print(f"CSV results written to: {csv_path}")
    print("\nNote: format fixtures only mimic file signatures; they are not valid PDF/DOCX/JPEG documents.")
    print("Latency measures local analysis functions, not Watchdog event-to-alert latency.")


if __name__ == "__main__":
    main()
