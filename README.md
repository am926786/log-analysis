# Log Analysis Script

# Overview

This Python script performs comprehensive log file analysis for cybersecurity monitoring. It extracts and analyzes key information from web server log files.

# Features

Count requests per IP address

Identify most frequently accessed endpoints

Detect potential brute force login attempts

Generate a CSV report with detailed findings

# Prerequisites

Python 3.7+

No external libraries required (uses standard Python libraries)

# Usage

# Preparation

Save your log file as sample.log in the same directory as the script

Ensure the log file follows the standard Apache/Nginx log format

# Running the Script

log_analysis.py

# Customization

Modify failed_login_threshold in analyze_log() to adjust suspicious activity detection

Change log_file_path in main() to analyze different log files

# Output

The script provides two types of output:

Terminal display with summary of:

Requests per IP address

Most accessed endpoint

Suspicious login activities

CSV file log_analysis_results.csv with detailed breakdown

# Log Format Support

Supports log entries in the following format:

CopyIP_ADDRESS - - [DATE] "METHOD /ENDPOINT HTTP/VERSION" STATUS_CODE SIZE

Example:

Copy192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512

# Error Handling

Handles missing log files

Gracefully processes log entries with parsing challenges
