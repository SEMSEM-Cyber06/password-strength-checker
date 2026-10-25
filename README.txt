# Password Strength Checker & Dictionary Attack Simulator

A Python command-line tool that analyzes a password and shows how weak or strong it is.

## Features
- Checks length, lowercase, uppercase, digits, symbols
- Calculates entropy and gives a Weak / Medium / Strong rating
- Estimates brute-force crack time (best, average, worst case)
- Simulates a dictionary attack using `passwords.txt`
- Gives recommendations and optionally shows the SHA-256 hash

## Usage
    python password_checker.py

Input is hidden while you type (uses `getpass`).

## Note
Educational project. Do not enter real passwords you use elsewhere.