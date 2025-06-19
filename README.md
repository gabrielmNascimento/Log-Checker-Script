# Log-Checker-Script
Python script that automates log checking:

1. Read logs from a log file

2. Look for suspicious keywords.

3. Save flagged entries into a report file for review.

How to Use:
   1. Save the script as log_checker.py.
   2. Change LOG_FILE_PATH to point to a real log file (/var/log/auth.log on Linux).
   3. Run it: python3 log_checker.py
   4. Check flagged_logs_report.txt for flagged entries.
