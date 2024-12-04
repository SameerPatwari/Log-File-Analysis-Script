# Log File Analysis
## Overview
This Python script analyzes server log files to provide insights on:

- **Requests per IP Address**: It counts how many requests each IP address made.
- **Most Accessed Endpoint**: It identifies the most frequently accessed endpoint.
- **Suspicious Activity Detection**: It flags IPs that have exceeded a specified threshold of failed login attempts.
## Features
- **IP Request Count**: Counts requests per IP address from the log file.
- **Most Accessed Endpoint**: Finds the most frequently accessed endpoint (GET, POST, etc.).
- **Suspicious Activity**: Flags IPs with excessive failed login attempts (401 HTTP status or "Invalid credentials" errors).
- **Error Handling**: The script includes basic error handling for file not found, file reading issues, and any exceptions that occur while processing or saving the data.

## Execution

- Clone this repository or download the script.

- Make sure there is a valid log file (e.g., sample.log).

- Run the script:

```
python log_analysis.py
```
- The analysis results will be printed to the console and saved to log_analysis_results.csv.

## Assumptions and Limitations
- The log file must be in a specific format, including IP addresses, HTTP methods (GET, POST, etc.), status codes (e.g., 200, 401), and endpoints.
- The script is designed to handle simple log entries and may not work properly with highly complex or non-standard log formats.
- The log file should contain valid entries for meaningful analysis.
