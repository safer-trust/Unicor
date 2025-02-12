from datetime import datetime, timedelta
from pathlib import Path
from utils.file import read_file

def parse_rfc3339_ns(timestamp):
    # Split the timestamp at the decimal point, if present
    parts = timestamp.strip().split('.')

    # Parse the datetime part as a datetime object
    dt = datetime.fromisoformat(parts[0])

    # Initialize nanoseconds to zero
    nanoseconds = 0

    # Handle the nanoseconds part (if present)
    if len(parts) > 1:
        nanoseconds_str = parts[1][:-1]

        # Convert nanoseconds to an integer (padded with zeros)
        nanoseconds = int(nanoseconds_str.ljust(9, '0')[:9])

    # Add nanoseconds to the datetime object
    dt = dt.replace(microsecond=nanoseconds // 1000)  # Convert nanoseconds to microseconds

    return dt

def get_time_from_pointer(path):
    pointer_path = Path(path)
    if pointer_path.is_file():
        pointer_file , _  = read_file(pointer_path)
        for line in pointer_file:
            timestamp = parse_rfc3339_ns(line)
            pointer_dt = timestamp
            return pointer_dt
    return None
