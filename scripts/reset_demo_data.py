from pathlib import Path
import shutil

FILES = [
    "data/raw/sandbox_runs.jsonl",
    "data/raw/process_samples.jsonl",
    "data/raw/syscall_events.jsonl",
    "data/raw/trace_aware_runs.jsonl",
    "data/processed/process_sample_summaries.jsonl",
    "data/processed/syscall_summaries.jsonl",
    "data/processed/behavioral_features.jsonl",
    "data/processed/detection_results.jsonl",
    "data/processed/ai_inference_results.jsonl",
    "data/processed/final_demo_results.jsonl",
]

DIRECTORIES = [
    "data/raw/strace",
]

REQUIRED_DIRECTORIES = [
    "data/raw",
    "data/processed",
    "data/models",
]

def main():
    for file_path in FILES:
        path = Path(file_path)
        if path.exists():
            path.unlink()

    for directory_path in DIRECTORIES:
        path = Path(directory_path)
        if path.exists():
            shutil.rmtree(path)

    for directory_path in REQUIRED_DIRECTORIES:
        Path(directory_path).mkdir(parents=True, exist_ok=True)

    Path("data/processed/detection_results.jsonl").touch()
    print("DEMO_DATA_RESET_DONE")
    print("detection_results_ready=true")

if __name__ == "__main__":
    main()
