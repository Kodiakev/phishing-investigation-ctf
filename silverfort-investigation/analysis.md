# Silverfort Security Investigation

## Executive Summary

This investigation analysed Windows Active Directory and Okta identity logs from 11–19 January 2025 to identify suspicious authentication activity and potential identity compromise.

Key findings:
- **On-premises:** Repeated Kerberos pre-authentication failures followed by successful authentication and 100 rapid service-ticket requests, consistent with possible password guessing and Kerberoasting.
- **Cloud identity:** API token `00T1wgdc76e1BvZIa5d7` was associated with repeated successful IdP client-secret-read events across multiple IP addresses.
- **Okta:** Suspicious policy and group changes, client-secret reads, and repeated MFA failures followed by successful authentication, account modification, MFA-factor activation, and SSO to AWS IAM Identity Center and Snowflake.

These findings indicate potential identity compromise and unauthorised administrative activity. The supplied logs do not conclusively prove credential theft, data exfiltration, or a direct link between the on-premises and cloud activity.

## 1. Methodology and Tooling

Python and pandas were used to load and filter the supplied CSV files, aggregate events by source IP and event type, build timelines, and correlate users, sessions, and API token identifiers. The scripts were executed in a WSL/Linux environment.

ChatGPT was used as an analytical support tool to help challenge hypotheses, organise findings, identify potential MITRE ATT&CK mappings, and draft the report. AI-generated interpretations were treated as hypotheses and checked against the supplied log fields and script output; the logs remained the basis of the findings.

The exercise was provided two days before submission. Analysis began on the submission day after other personal commitments and seeking clarification from May. Within the available working time, the investigation prioritised authentication anomalies, identity-provider changes, API token activity, and potential indicators of compromise. Additional endpoint and cloud-service telemetry would be needed to validate several hypotheses.

## 2. Part One — On-Premises Active Directory

### Kerberos authentication failures

On 19 January 2025, 31 Event ID 4771 Kerberos pre-authentication failures for `rm_user` originated from `::ffff:10.30.24.249`, targeting `krbtgt/rm-esx` with failure code `0x18`. A successful Event ID 4768 TGT request for `rm_user` followed at 15:15:17 UTC.

**Assessment:** This pattern is consistent with possible password guessing or repeated incorrect-password attempts followed by successful authentication. The logs do not establish whether the successful login was malicious.

### Rapid service-ticket requests

At approximately 15:16:18–15:16:21 UTC, the same source generated 100 distinct Event ID 4769 service-ticket requests involving `RonTestUser1` through `RonTestUser100`. The requests occurred within approximately three seconds and included ticket encryption type `0x17` (RC4-HMAC).

**Assessment:** The volume and speed are consistent with possible Kerberos service-ticket enumeration or Kerberoasting. The logs do not prove that tickets were extracted or cracked, and the supplied records do not establish whether the accounts had relevant SPNs.

### Subsequent authentication and directory activity

Further events included successful authentication involving `RonTestUser42`, Type 3 network logons, Event ID 4672 special-privilege assignments, and activity involving `sfadmin`. Two Event ID 4662 records at approximately 15:25:24 UTC involved `RonTestUser42` and a domain-level directory object.

**Assessment:** These events warrant investigation, but Event ID 4672 does not independently prove privilege escalation. The 4662 records lacked the extended-right GUID needed to conclude that DCSync occurred. The available evidence also does not prove that `sfadmin` was compromised.

## 3. Part Two — Cloud Identity and Okta

### API token and client-secret reads

API token `00T1wgdc76e1BvZIa5d7` appeared in successful `system.idp.lifecycle.read_client_secret` events across multiple dates and IP addresses between 11 and 19 January. Related activity included repeated `system.org.rate_limit.warning` events.

**Assessment:** This is a significant lead. Possible explanations include authorised automation or unauthorised use of a privileged token. Successful audit events do not, by themselves, prove that secret values were exfiltrated or misused. Token ownership, intended use, scopes, and source infrastructure should be validated.

### Administrative changes on 19 January

Activity from `79.177.131.197` between approximately 12:09 and 12:24 UTC included sign-on challenges, MFA and OAuth events, Admin Console access, creation of a `No MFA` policy and `NoMFA` group, group changes, policy updates, IdP client-secret reads, and Snowflake application activity.

**Assessment:** The sequence raises concern about possible identity compromise or administrative misuse. The policy name alone does not prove that MFA was actually disabled, and the logs do not establish that a secret was copied or that Snowflake data was accessed.

### MFA and account changes

At approximately 12:27–12:29 UTC, `212.97.69.32` generated ten failed MFA attempts for Dwight Schrute, followed by successful verification, a password update/reset event, MFA-factor activation, and SSO to AWS IAM Identity Center and Snowflake. The events shared session context. The IP was geolocated to Astana, Kazakhstan.

**Assessment:** This sequence is consistent with possible account takeover and persistence. Geolocation is a risk indicator, not proof of malicious intent. SSO events do not independently prove access to cloud resources or data exfiltration.

## 4. Consolidated Timeline

| Date/time (UTC) | Evidence | Assessment |
|---|---|---|
| 11–12 Jan | Successful IdP client-secret reads and rate-limit warnings involving the API token | Validate token ownership and expected automation |
| 13–17 Jan | Same token associated with secret reads from additional IPs | Repeated multi-IP activity; purpose unconfirmed |
| 18–19 Jan, around 06:45 | Secret reads and rate-limit warnings from `18.196.17.130` | Investigate API activity |
| 19 Jan, 12:09–12:24 | Authentication, policy/group changes, secret reads and application changes from `79.177.131.197` | Potential identity compromise or administrative misuse |
| 19 Jan, 12:27–12:29 | MFA failures followed by successful authentication, account changes and application SSO from `212.97.69.32` | Strong indicator of possible account takeover |
| 19 Jan, 15:14–15:16 | Kerberos failures followed by successful authentication and 100 rapid service-ticket requests | Possible password guessing and Kerberos abuse |
| 19 Jan, 15:19–15:25 | Further authentication, privilege-related and directory-object events | Investigate potential account misuse |

The supplied evidence does not establish a direct causal link between the on-premises and cloud activity.

## 5. Part Three — Response and Resilience Plan

### Immediate — contain the threat

1. Preserve relevant Windows, Okta, AWS, and Snowflake logs.
2. Revoke suspicious sessions and API tokens; reset credentials or disable accounts where compromise is suspected.
3. Validate the repeated IdP client-secret reads and rotate affected secrets if exposure cannot be ruled out.
4. Review the `No MFA` policy, group memberships, OAuth configuration, and application assignments; reverse unauthorised changes.
5. Review AWS CloudTrail and Snowflake login/query history to determine the extent of downstream access.

**Reason for sequencing:** Preserve evidence where practicable, contain potentially active access, secure affected credentials, and then establish the scope of impact. Coordinate secret rotation with dependent applications to avoid unnecessary disruption.

### Near future — strengthen controls and detection

1. Audit administrators, API tokens, OAuth clients, and service accounts for excessive or unauthorised access.
2. Enforce phishing-resistant MFA for administrators and sensitive accounts where supported.
3. Restrict identity administration to approved devices and trusted access paths where practical.
4. Add detections for MFA failures followed by success, suspicious factor changes, repeated client-secret reads, policy changes, and unusual Kerberos ticket-request bursts.
5. Review service-account SPNs, password strength, and unnecessary RC4 use.
6. Correlate Windows, Okta, AWS, and Snowflake logs in central monitoring.

**Reason for sequencing:** Validate access and configuration first, then strengthen preventive controls and implement detections informed by the observed behaviour.

### Future — build durable resilience

1. Apply least privilege, regular access reviews, and separation of administrative duties.
2. Establish ownership, expiry, rotation, and monitoring for API tokens and application secrets.
3. Create incident-response playbooks for account takeover, token misuse, MFA manipulation, and Kerberos abuse.
4. Run regular threat hunts and controlled simulations to test detections and response procedures.
5. Review detection coverage, response times, and outstanding risks with accountable owners.

**Reason for sequencing:** Longer-term architecture and process changes build on containment and configuration improvements, making similar attacks harder to execute and easier to detect.

### Success criteria

- Suspicious sessions and unauthorised credentials are revoked or secured.
- Identity policies and permissions are validated and corrected where needed.
- AWS and Snowflake investigations establish the known extent of downstream activity.
- Detection rules are tested against the observed patterns.
- Long-term actions have named owners and review dates.

## 6. MITRE ATT&CK Mapping

| Technique | Relevance | Confidence |
|---|---|---|
| T1110.001 — Password Guessing | Repeated Kerberos pre-authentication failures followed by success | Possible |
| T1558.003 — Kerberoasting | Rapid service-ticket requests across many accounts | Suspected; validate SPNs and ticket handling |
| T1078 — Valid Accounts | Successful authentication and SSO amid suspicious activity | Consistent with observed behaviour; malicious use unconfirmed |
| T1098 — Account Manipulation | Group membership and identity configuration changes | Observed changes; malicious intent requires validation |
| T1556.006 — Multi-Factor Authentication | Potential MFA-policy weakening or factor changes | Conditional on validating configuration impact |

These mappings are investigative hypotheses, not confirmation that every technique was successfully executed.

## 7. Limitations and Conclusion

The analysis was limited to the supplied CSV records. Endpoint telemetry, network evidence, AWS CloudTrail, Snowflake query history, and independent configuration records were not available to confirm downstream impact.

The logs do not conclusively establish successful Kerberoasting, DCSync, credential theft, secret misuse, or data exfiltration. The relationship between the historical API-token activity, the 19 January cloud activity, and the on-premises events remains unconfirmed.

Overall, the evidence supports a high-priority identity-security investigation. The recommended approach is to contain potentially compromised identities and credentials, restore trusted controls, determine the extent of downstream access, and improve identity-focused prevention and detection.
