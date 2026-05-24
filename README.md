# AI-Enhanced Linux Process Sandbox for Behavioral Threat Prevention

## Overview

This project is a Linux security system that runs processes inside a controlled sandbox, monitors their runtime behavior, extracts behavioral features, evaluates risk using rule-based detection and machine learning, and presents the results through an API and dashboard.

## Academic Context

This project is prepared for a fourth-year Informatics Engineering systems course. It focuses on Linux process isolation, behavioral monitoring, threat detection, risk scoring, and AI-assisted anomaly detection.

## Core Idea

Traditional security tools often rely on known signatures. This project focuses on behavior. Instead of asking whether a file is already known as malware, the system observes what a process does while running.

## Main Features

- Linux process execution control
- Runtime behavior monitoring
- CPU and memory tracking
- File activity detection
- Child process tracking
- Syscall tracing using strace
- Rule-based threat detection
- AI-based anomaly detection
- Risk scoring
- Alerts
- API layer
- Future dashboard

## Current Status

Phase 1 is completed.

Phase 2 is in progress.

## Planned Stack

- Ubuntu Linux
- Python
- FastAPI
- SQLite
- SQLAlchemy
- psutil
- strace
- pandas
- numpy
- scikit-learn

## Detection Approach

The project uses a hybrid detection approach:

1. Rule-based detection for clear suspicious behaviors.
2. Machine-learning-based anomaly detection for unusual process behavior.
3. Final risk scoring that combines both outputs.

## Demo Strategy

The final demo will include:

1. A safe process.
2. A suspicious process.
3. A ransomware-like safe simulation inside a test directory.
