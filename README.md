# Advanced Log Analyzer
## jahid whatsapp: 8801309495010

A Python-based log analysis tool that parses structured log files, validates log entries, detects suspicious login activity, validates IP addresses, and generates an analysis report.

This project is built as a **practical Python project** to strengthen skills in **Regular Expressions, File Handling, OOP, Data Validation, and Basic Security Analysis**.

---

## 📌 Project Overview

The **Advanced Log Analyzer** reads log data from a text file and processes each log entry using Python.

The program:

* Parses structured log entries using **Regular Expressions**
* Separates valid and invalid logs
* Validates dates and IP addresses
* Detects suspicious IP addresses based on failed login attempts
* Detects failed login attempts from special usernames
* Counts successful and failed logins
* Counts log levels
* Finds unique users and IP addresses
* Generates a final `report.txt` file

---

## 🚀 Features

### 1. Log Parsing

The program uses Python's `re` module to extract information from each log line.

Extracted fields include:

* Date
* Time
* Log level
* Username
* IP address
* Action
* Status
* Reason
* File
* File size

Example:

```text
2026-09-01 14:30:25 [INFO] user=admin ip=192.168.1.10 action=login status=failed reason="invalid password"
```

---

### 2. Invalid Log Detection

Logs that don't match the expected format are automatically detected and stored separately.

The program maintains:

```python
valid_log
invalid_log
```

This makes it possible to analyze both valid and malformed log entries.

---

### 3. Suspicious IP Detection 🚨

The analyzer counts failed login attempts for each IP address.

If an IP has **more than 5 failed login attempts**, it is considered suspicious.

Example:

```text
Suspicious ip: 192.168.1.50, Failed attempts: 8
```

---

### 4. Suspicious Username Detection

The program monitors failed login attempts involving potentially sensitive/common usernames:

```text
admin
root
administrator
test
guest
```

This can help identify possible brute-force or unauthorized login attempts.

---

### 5. IP Address Validation

The analyzer checks whether each IPv4 address contains valid octets.

For example:

```text
192.168.1.10   → Valid
192.168.1.300  → Invalid
```

Each IP is categorized into:

```text
Valid IP
Invalid IP
```

---

### 6. Log Level Analysis

The program counts how many times each log level appears.

Example:

```text
INFO      15
WARNING    7
ERROR      4
```

---

### 7. Login Statistics

The analyzer calculates:

* Successful logins
* Failed logins
* Total logs
* Valid logs
* Invalid logs

---

### 8. Unique User & IP Analysis

The program identifies:

* Unique users
* Unique IP addresses
* Which users are associated with each IP

Example internal structure:

```python
{
    "192.168.1.10": ["john", "admin"],
    "192.168.1.20": ["alice"]
}
```

---

### 9. Report Generation 📄

After analysis, the program generates:

```text
report.txt
```

The report contains information such as:

```text
================================ LOG ANALYSIS ================================

Total logs           : 100
Valid logs           : 92
Invalid logs         : 8

INFO                 : 60
WARNING              : 20
ERROR                : 12

Successful login     : 65
Failed login         : 27

Unique users         : 15
Unique IPs           : 20

Suspicious IPs       : 3

========================================
```

---

## 🛠️ Technologies Used

* **Python 3**
* `re` — Regular Expressions
* `datetime` — Date validation
* File Handling
* Object-Oriented Programming (OOP)

---

## 📂 Project Structure

```text
advanced-log-analyzer/
│
├── main.py
├── data.txt
├── report.txt
└── README.md
```

> `report.txt` is generated automatically after running the program.

---

## ▶️ How to Run

### 1. Clone the repository

```bash
git clone https://github.com/your-username/advanced-log-analyzer.git
```

### 2. Enter the project directory

```bash
cd advanced-log-analyzer
```

### 3. Make sure `data.txt` exists

Place your log data inside:

```text
data.txt
```

### 4. Run the program

```bash
python3 main.py
```

The program will analyze the logs and generate:

```text
report.txt
```

---

## 📝 Input Format

The current parser expects logs in a structured format similar to:

```text
2026-09-01 12:10:20 [INFO] user=john ip=192.168.1.10 action=login status=success
2026-09-01 12:15:30 [WARNING] user=admin ip=192.168.1.50 action=login status=failed reason="invalid password"
2026-09-01 12:20:45 [INFO] user=root ip=10.0.0.5 action=login status=failed reason="wrong password"
```

Optional fields such as `status`, `reason`, `file`, and `size` are supported according to the parser's current format.

---

## 🧠 Python Concepts Practiced

This project was designed to practice several important Python concepts:

### Core Python

* Variables
* Conditions
* Loops
* Functions
* Lists
* Dictionaries
* Strings

### Intermediate Python

* Classes
* Objects
* Constructors
* Methods
* File handling
* Exception handling

### Advanced / Practical Python

* Regular Expressions
* Named regex groups
* Data validation
* Object-based data storage
* Log analysis
* Basic security analysis

---

## 🔍 Example Regex Concept

The project uses **named capture groups** to extract log information.

For example:

```python
(?P<user>\w+)
```

This allows the program to extract the username directly:

```python
data.group('user')
```

Similarly:

```python
data.group('date')
data.group('time')
data.group('level')
data.group('ip')
data.group('action')
```

can be used to retrieve different parts of a log entry.

---

## 🎯 Learning Goals

The main goal of this project is not only to create a working program, but also to practice how Python can be used for real-world data processing and basic security-related analysis.

Through this project, I practiced:

```text
Regex
   ↓
Log Parsing
   ↓
Data Validation
   ↓
OOP
   ↓
Security Analysis
   ↓
Report Generation
```

---

## 🚧 Future Improvements

Possible future improvements include:

* [ ] Support multiple log formats
* [ ] Improve date validation
* [ ] Improve IP validation using Python's `ipaddress` module
* [ ] Add command-line arguments
* [ ] Add CSV/JSON export
* [ ] Add configurable suspicious-IP threshold
* [ ] Add more security detection rules
* [ ] Add unit tests
* [ ] Add logging for the analyzer itself
* [ ] Create a CLI interface
* [ ] Add visualization/dashboard
* [ ] Support large log files efficiently

---

## 📚 Project Status

**Status:** ✅ Completed

This project is part of my long-term Python learning roadmap and focuses on building practical, project-based Python skills.

---

## 👨‍💻 Author

**Jahid**

Learning Python through practical projects and gradually moving toward:

```text
Python
  ↓
Automation
  ↓
AI
  ↓
Cybersecurity
  ↓
AI + Cybersecurity
```

---

## ⭐ If You Find This Project Useful

Feel free to explore the code, suggest improvements, or use the project as a learning reference.
