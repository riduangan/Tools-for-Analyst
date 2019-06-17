# Tools-for-Analyst
Jump bag tools for analyst 
- need update
- need link


Dividing into sections, based on your objectives

# Imaging


# Static & Dynamic Analysis
Notepad ++: Advanced text editor, used in order to view any javascript files.
IDA Pro Free: x86 Disassembler.
Ollydbg: x86 Disassembler.
WinDbg: x86-based, x64-based, or ARM debugger.
IlSpy: .NET decompiler.
CFF Explorer: PE Editor.
PE View: PE File Viewer.
PEID: Used to determine if a file is packed, and other basic info.
Resource Hacker: Allows us to view the resources that an executable file calls.
Power_dump.py https://github.com/chrisjd20/power_dump
Olevba  :Python Oletools. Can extract Macro’s from documents and display auto run settings.
From elevated console :Pip install oletools (Linux)
Py -2 -m pip install oletools (Windows)
CRITS: Malware analysis and IOC storage platform. Handy for quick analysis on Malware.
Can extract macros and javascript embedded in documents
Malzilla:  Malware hunting tool.
Streams:Sys internals tool for viewing Alternative Data Streams attached to files.



# Memory Forensic
 WinDbg –Kernel debugger for Windows systems
 Muninn – A script to automate portions of analysis using Volatility
 DAMM –Differential Analysis of Malware in Memory, built on Volatility
 FindAES –Find AES encryption keys in memory
 Volatility — Advanced memory forensics framework



# Malware Detection

YARA – Pattern matching tool for analysts.
Yara rules generator – Generate YARA rules based on a set of malware samples. Also, contains a good strings DB to avoid false positives.
File Scanning Framework – Modular, recursive file scanning solution.
hash deep – Compute digest hashes with a variety of algorithms.
Loki – Host-based scanner for IOCs.
Malfunction – Catalog and compare malware at a function level.
MASTIFF – Static analysis framework.


# Web-Domain Analysis

SpamCop – IP-based spam block list.
SpamHaus – Block list based on domains and IPs.
Sucuri SiteCheck – Free Website Malware and Security Scanner.
TekDefense Automatic – OSINT tool for gathering information about URLs, IPs, or hashes.
URLQuery – Free URL Scanner.
IPinfo – Gather information about an IP or domain by searching online resources.
Whois – DomainTools free online whois search.
mail checker – Cross-language temporary email detection library.


# Network Interaction Analysis

Tcpdump – Collect network traffic.
tcpick – Trach and reassemble TCP streams from network traffic.
tcpxtract – Extract files from network traffic.
Wireshark – The network traffic analysis tool.
CapTipper – Malicious HTTP traffic explorer.
chopshop – Protocol analysis and decoding framework.
CloudShark – Web-based tool for packet analysis and malware traffic detection


# Debugging and Debugger (Debug's brother)

obj dump – Part of GNU Binutils, for static analysis of Linux binaries.
OllyDbg – An assembly-level debugger for Windows executable
FPort – Reports open TCP/IP and UDP ports in a live system and map them to the owning application.
GDB – The GNU debugger.
IDA Pro – Windows disassembler and debugger, with a free evaluation version.
Immunity Debugger – Debugger for malware analysis and more, with a Python API.

# Analysing URL

Firebug – Firefox extension for web development.
Java Decompiler – Decompile and inspect Java apps.
jsunpack-n – A javascript unpacker that emulates browser functionality.
Krakatau – Java decompiler, assembler, and disassembler.
Malzilla – Analyze malicious web pages.

# Sandbox Techniques

firmware.re – Unpacks, scans and analyzes almost any firmware package.
Hybrid Analysis – Online malware analysis tool, powered by VxSandbox.
IRMA – An asynchronous and customizable analysis platform for suspicious files.
Cuckoo Sandbox – Open source, self-hosted sandbox, and automated analysis system.
cuckoo-modified – Modified version of Cuckoo Sandbox released under the GPL.
PDF Examiner – Analyse suspicious PDF files.
ProcDot – A graphical malware analysis toolkit.
Recomposer – A helper script for safely uploading binaries to sandbox sites.
Sand droid – Automatic and complete Android application analysis system.
