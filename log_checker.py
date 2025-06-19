# Python’s regular expression library, used for searching suspicious patterns in log entries.
import re
# Lets us get the current date/time to timestamp the report file.
from datetime import datetime

#  --- Configuration ---
LOG_FILE_PATH = "system.log"  # The path of the log file to be analyzed. You should change based on where is your log file. Replace with "/var/log/syslog" or "auth.log" on Linux systems.
OUTPUT_FILE = "flagged_logs_report.txt" # Where the suspicious logs will be saved.

# --- Define suspicious patterns/keywords (Keywords to search in log entries) ---
SUSPICIOUS_PATTERNS = [ 
    r"failed",
    r"unauthorized",
    r"denied",
    r"invalid",
    r"error",
    r"segfault",
    r"attack",
    r"malware",
    r"exploit"
]

def load_log_file(path):
    # Tries to open the log file at the given path.
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines() # Reads all lines into a list.
    except FileNotFoundError:
        # If the file is missing will print an error.
        print(f"[!] Log file not found: {path}")
        return []

def check_logs(log_lines, patterns):
    flagged_lines = []
    for line in log_lines:
        for pattern in patterns: # For each log line, it loops through all suspicious patterns.
            if re.search(pattern, line, re.IGNORECASE): # If a pattern is found using re.search(), it adds the line to the flagged_lines list. (re.IGNORECASE makes the search case-insensitive.)
                flagged_lines.append(line.strip())
                break
    return flagged_lines

def write_report(lines, output_path):
    with open(output_path, "w") as f: # Opens the output file for writing.
        f.write(f"Suspicious Log Report - {datetime.now()}\n\n") # Adds a header with the current date/time.
        for line in lines:
            f.write(line + "\n")
    print(f"[+] Report saved to {output_path}") # Confirms the report was saved.

def main():
    print("[*] Starting log analysis...")
    # Load the logs:
    logs = load_log_file(LOG_FILE_PATH)
    if not logs:
        return # If the file is empty or not found, it stops.
    flagged = check_logs(logs, SUSPICIOUS_PATTERNS) # Otherwise, it checks logs for suspicious entries.
    if flagged:
        write_report(flagged, OUTPUT_FILE) # If any are found, it writes a report.
    else:
        print("[+] No suspicious entries found.") # If nothing is found, it prints a message.

if __name__ == "__main__":
    main()
