# Bulk URL Checker Virustotal

## Description

This script allows you to check a list of URLs against the VirusTotal database to identify potentially malicious URLs. It reads URLs from an input file, queries the VirusTotal API for each URL, and writes the results to an output file.

## Features

- Read URLs from a text file
- Query VirusTotal API for each URL
- Write the results to an output file

## Prerequisites

### Data Cleaning

    grep -Eo 'http[s]?:\/\/(www\.)?[-a-zA-Z0-9@:%.\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%\+.~#?&//=]*)'

    grep -E "https?:\/\/(www\.)?[-a-zA-Z0–9@:%.\+~#=]{1,256}\.[a-zA-Z0–9()]{1,6}\b([-a-zA-Z0–9()@:%\+.~#?&//=]*)"



Before running the script, make sure you have Python 3 installed. You also need to install the required dependencies and obtain a VirusTotal API key.

## Installation

1. Clone the repository or download the script.

    ```sh
    git clone https://github.com/yourusername/virustotal-checker.git
    cd virustotal-checker
    ```

2. Install the required Python packages using `pip`.

    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Obtain a VirusTotal API key by creating an account on [VirusTotal](https://www.virustotal.com/) and navigating to your API key settings.

2. Run the script with the input file, output file, and your API key as arguments.

    ```sh
    python bulk-url-checker.py input.txt
    ```


## Example

Assuming you have a file named `input.txt` with the following content:

    ```
    http://example.com
    http://malicious-site.com
    ```

