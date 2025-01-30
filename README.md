**Php's Anti-Virus**
Php's Anti-Virus is a lightweight malware scanning and quarantine tool designed to detect and handle suspicious files. It scans directories for known malware, performs heuristic analysis, and monitors running processes for potential threats.

Overview
This project was originally created by Mokujyn. However, the code was incomplete, and I Joshua contributed by completing the implementation, adding key functionalities, optimizing detection mechanisms, and ensuring smooth execution.

Features
•	File Scanning – Identifies malware based on hash signatures.
•	Heuristic Analysis – Detects suspicious code patterns.
•	Large File Scanning – Uses memory-mapped file access for efficiency.
•	Process Monitoring – Continuously scans running processes.
•	Quarantine System – Moves suspicious files for further inspection.
•	Logging – Records all detections and actions taken.

Requirements
•	Python 3.x
•	Install dependencies:
pip install psutil plyer

Usage
1.	Run the script and enter the directory path to scan.
2.	The program will scan files and quarantine any that match known threats or contain suspicious patterns.
3.	It will also monitor running processes and log findings in antivirus_results.txt.

Contributors
•	Mokujyn– Original author, initial concept, and partial implementation.
•	Joshua – Completed and improved the code, and added core functionality.

License
This project is licensed under the MIT License.

