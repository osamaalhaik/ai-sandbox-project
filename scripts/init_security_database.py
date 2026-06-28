import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import inspect
from app.web_platform.database import Base, engine
import app.web_platform.models

def main():
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    tables = sorted(inspector.get_table_names())

    print("DATABASE_INITIALIZED")
    for table in tables:
        print(table)

if __name__ == "__main__":
    main()
