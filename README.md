# phishing-investigation-ctf
Phishing analysis, network investigation and Python security automation

# Phishing Investigation CTF — DarkWater Financial

## Overview

This project documents a hands-on cybersecurity CTF focused on investigating a simulated phishing website. The objective was to understand its browser-validation mechanisms, identify how submitted information was collected and transmitted, analyse network traffic, and develop a Python-based browser automation agent to reproduce the workflow using controlled test credentials.

This was my first hands-on investigation of this type, giving me practical experience in web analysis, threat intelligence, network investigation, and security automation.

## Objectives

- Investigate the website's HTML and JavaScript behaviour.
- Analyse its browser and anti-automation checks.
- Identify how the login workflow handled submitted credentials.
- Inspect network requests and custom HTTP headers.
- Decode and analyse the captured payload.
- Automate the investigation using Python and Playwright.
- Document the findings, troubleshooting process, and lessons learned.

## Methodology

### 1. Initial reconnaissance

Inspected the initial webpage, its HTML structure, and loaded JavaScript resources. Identified a browser-validation workflow that controlled access to the simulated banking interface.

### 2. JavaScript analysis

Reviewed the website's client-side scripts to understand its behaviour.

Key findings included:

- `worker.js` implemented browser and automation detection.
- The website used `darkwater_access_blocked` and `darkwater_access_verified` cookies to manage access.
- Depending on the validation result, the browser was directed towards `/blocked` or `/landing`.
- `login.js` handled the simulated login form and prepared a data payload.

### 3. Network traffic analysis

Used browser developer tools to inspect HTTP requests and responses.

Investigated the `/session` endpoint and the custom `X-Payload` request header. Also identified a request to GeoJS for IP and geographic/network metadata enrichment.

### 4. Payload analysis

The login script constructed a JSON object containing the submitted test credentials, a timestamp, and available IP, geographic, and network metadata.

The JSON payload was Base64-encoded twice and transmitted in the `X-Payload` header of a GET request to `/session`.

The interface displayed an "Invalid credentials" message after submission. Analysis showed that the workflow was collecting and transmitting the submitted data rather than behaving like a conventional authentication flow.

### 5. Python automation

Developed a Playwright-based Python agent to automate browser navigation, interact with the simulated login form, capture the `/session` request, decode the payload, and save redacted evidence.

The agent successfully reproduced the workflow using controlled test credentials.

## Key Findings

- Browser-validation logic controlled access to the simulated banking interface.
- Client-side JavaScript collected submitted credentials and contextual metadata.
- GeoJS was used to enrich the collected information.
- The payload was double Base64-encoded and transmitted through a custom HTTP header.
- The login interface's error message did not accurately represent the underlying data-collection behaviour.
- Network inspection and payload decoding provided evidence of the information being transmitted.

## Tools and Technologies

- Python
- Playwright
- Chromium
- Browser Developer Tools
- HTTP request/response analysis
- JavaScript analysis
- Base64 decoding
- Kali Linux

## Challenges and Troubleshooting

During implementation, I resolved several environment and automation issues:

- Configuring Python virtual environments and dependencies.
- Troubleshooting package-manager and repository-signing issues in Kali Linux.
- Installing missing Chromium system libraries.
- Investigating and addressing the site's browser-automation detection in the controlled CTF environment.

## Outcome

Successfully investigated the simulated phishing workflow, identified its data-collection and transmission mechanisms, and developed a working Python agent to reproduce the interaction and capture the resulting payload.

The project reinforced the importance of correlating client-side code, browser behaviour, and network telemetry rather than relying solely on the user-facing interface.

## Skills Demonstrated

- Web and JavaScript investigation
- Network traffic analysis
- Threat intelligence and phishing analysis
- Security automation
- Python scripting
- Evidence collection and documentation
- Technical troubleshooting

## Disclaimer

This project was conducted as a controlled CTF investigation using test credentials. Any included evidence must be sanitised to remove personal information, IP addresses, session tokens, cookies, and other sensitive data. The automation is intended for authorised lab environments only.
