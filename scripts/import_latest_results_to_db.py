from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.web_platform.database import Base, SessionLocal, engine
from app.web_platform.ingest import import_jsonl_results

def main():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as session:
        result = import_jsonl_results(session)

    print("DATABASE_IMPORT_DONE")
    print(result)

if __name__ == "__main__":
    main()
