import pandas as pd

df = pd.read_csv("/mnt/c/Users/The Leviathan/Downloads/On-premise Attack Scenario (1).csv")
df["Date and Time"] = pd.to_datetime(df["Date and Time"])

source_ip = "::ffff:10.30.24.249"

events = df[
    df["Client Address"].astype(str).eq(source_ip)
].sort_values("Date and Time")

columns = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Client Address",
    "Service Name",
    "Failure Code",
    "Result Code"
]

print(events[columns].to_string(index=False))

# Inspect the actual CSV schema
print("\nAvailable columns:")
print(df.columns.tolist())

# Filter Kerberos service-ticket events
tickets = df[df["Event ID"].astype(str).str.strip() == "4769"]

print("\nEvent ID 4769 summary:")
print(f"Total service-ticket events: {len(tickets)}")

# Display all available fields for a sample
print("\nSample service-ticket events:")
print(tickets.head(10).to_string(index=False))

# Summarise encryption types for Event ID 4769
tickets = df[df["Event ID"].astype(str).str.strip() == "4769"]

print("\nTicket encryption type counts:")
print(
    tickets["Ticket Encryption Type"]
    .fillna("Missing")
    .value_counts()
    .to_string()
)

print("\nEncryption types by target service:")
print(
    tickets.groupby(
        ["Service Name", "Ticket Encryption Type"],
        dropna=False
    ).size().sort_values(ascending=False).to_string()
)

# Investigate potential follow-on activity
df["Event ID"] = df["Event ID"].astype(str).str.strip()

event_ids = ["4624", "4672", "4799", "4662", "4688"]

follow_on = df[df["Event ID"].isin(event_ids)].copy()

columns = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Subject",
    "New Logon",
    "Logon Type",
    "Process Name",
    "Source Network Address",
    "Client Address",
    "Object Name",
    "Accesses",
    "Group Name",
]

columns = [c for c in columns if c in follow_on.columns]

print("\n=== Follow-on investigation ===")
print(f"Matching events: {len(follow_on)}")
print(
    follow_on[columns]
    .sort_values("Date and Time")
    .to_string(index=False)
)

# Examine raw Active Directory object-access events
events_4662 = df[
    df["Event ID"].astype(str).str.strip() == "4662"
]

fields = [
    "Date and Time",
    "Account Name",
    "Security ID",
    "Object Name",
    "Object Type",
    "Operation",
    "Operation Type",
    "Accesses",
    "Access Mask",
    "Properties",
    "Additional Information",
]

fields = [c for c in fields if c in events_4662.columns]

print("\n=== Raw Event ID 4662 details ===")
print(events_4662[fields].to_string(index=False))

events_4662 = df[
    df["Event ID"].astype(str).str.strip() == "4662"
]

for col in [
    "Date and Time",
    "Subject",
    "Security ID",
    "Account Name",
    "Object Name",
    "Object Type",
    "Access Mask",
    "Properties",
    "Additional Information",
]:
    if col in events_4662.columns:
        print(f"\n--- {col} ---")
        print(events_4662[col].to_string(index=False))
target_accounts = ["rm_user", "RonTestUser42", "sfadmin"]

events = df[
    df["Account Name"].astype(str).str.strip().isin(target_accounts)
].copy()

events["Date and Time"] = pd.to_datetime(
    events["Date and Time"], errors="coerce"
)

events = events.sort_values("Date and Time")

columns = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Logon Type",
    "Source Network Address",
    "Process Name",
    "Privileges",
    "Group Name",
    "Service Name",
    "Ticket Encryption Type",
    "Failure Code",
]

columns = [c for c in columns if c in events.columns]

print(events[columns].to_string(index=False))


# Inspect logon IDs and detailed logon fields for the accounts of interest

target_accounts = ["rm_user", "RonTestUser42", "sfadmin"]

subset = df[
    df["Account Name"].astype(str).str.strip().isin(target_accounts)
].copy()

subset["Date and Time"] = pd.to_datetime(
    subset["Date and Time"], errors="coerce"
)

subset = subset.sort_values("Date and Time")

fields = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Security ID",
    "Subject",
    "Logon ID",
    "Linked Logon ID",
    "Logon Type",
    "Source Network Address",
    "Workstation Name",
    "Process Name",
    "Privileges",
    "Target Server Name",
    "Service Name",
]

fields = [c for c in fields if c in subset.columns]

print(subset[fields].to_string(index=False))


# Inspect all Event ID 4799 records

events_4799 = df[
    df["Event ID"].astype(str).str.strip() == "4799"
].copy()

fields = [
    "Date and Time",
    "Subject",
    "Security ID",
    "Account Name",
    "Logon ID",
    "Process Name",
    "Process ID",
    "Object Name",
    "Group Name",
    "Group Domain",
    "Source Network Address",
    "Workstation Name",
]

fields = [c for c in fields if c in events_4799.columns]

print(events_4799[fields].to_string(index=False))


# Summarise events associated with the suspicious source IP

source_ip = "10.30.24.249"

source_events = df[
    df["Source Network Address"].astype(str).str.strip()
    == source_ip
].copy()

source_events["Date and Time"] = pd.to_datetime(
    source_events["Date and Time"], errors="coerce"
)

print("=== Event counts by ID ===")
print(source_events["Event ID"].value_counts().sort_index())

print("\n=== Timeline by account and event ===")

fields = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Logon Type",
    "Source Network Address",
    "Target Server Name",
    "Service Name",
    "Ticket Encryption Type",
    "Failure Code",
]

fields = [c for c in fields if c in source_events.columns]

print(
    source_events.sort_values("Date and Time")[fields]
    .to_string(index=False)
)


# Inspect Event ID 4769 service-ticket requests

tickets = df[
    df["Event ID"].astype(str).str.strip() == "4769"
].copy()

tickets["Date and Time"] = pd.to_datetime(
    tickets["Date and Time"], errors="coerce"
)

# Focus on the burst between 15:16:00 and 15:17:00
burst = tickets[
    (tickets["Date and Time"] >= "2025-01-19 15:16:00")
    & (tickets["Date and Time"] < "2025-01-19 15:17:00")
].copy()

print("Total Event 4769 records in burst:", len(burst))

# Show available fields that help identify requested accounts/services
fields = [
    "Date and Time",
    "Account Name",
    "Service Name",
    "Target Server Name",
    "Ticket Encryption Type",
    "Session Encryption Type",
    "Failure Code",
    "Result Code",
]

fields = [c for c in fields if c in burst.columns]

print("\n=== Ticket request details ===")
print(burst[fields].to_string(index=False))

print("\n=== Ticket encryption counts ===")
if "Ticket Encryption Type" in burst.columns:
    print(burst["Ticket Encryption Type"].value_counts(dropna=False))

print("\n=== Distinct service names ===")
if "Service Name" in burst.columns:
    print("Unique services:", burst["Service Name"].nunique())
    print(burst["Service Name"].value_counts(dropna=False).to_string())


# Inspect the relevant fields for the 100 RonTestUser ticket requests

tickets = df[
    (df["Event ID"].astype(str).str.strip() == "4769")
    & df["Service Name"].astype(str).str.match(
        r"RonTestUser\d+$", na=False
    )
].copy()

print("Matching ticket requests:", len(tickets))

fields = [
    "Date and Time",
    "Account Name",
    "Service Name",
    "Service ID",
    "Service Information",
    "MSDS-SupportedEncryptionTypes",
    "Available Keys",
    "Ticket Encryption Type",
    "Session Encryption Type",
    "Failure Code",
]

fields = [c for c in fields if c in tickets.columns]

print(tickets[fields].to_string(index=False))

print("\n=== Available SPN-related columns ===")
for col in df.columns:
    if any(term in col.lower() for term in ["spn", "service principal"]):
        print(col)


# Quantify the service-ticket burst

tickets = df[
    df["Event ID"].astype(str).str.strip() == "4769"
].copy()

tickets["Date and Time"] = pd.to_datetime(
    tickets["Date and Time"], errors="coerce"
)

tickets = tickets.dropna(subset=["Date and Time"])

# Identify the 100 sequentially named targets
mask = tickets["Service Name"].astype(str).str.fullmatch(
    r"RonTestUser\d+"
)

targets = tickets[mask].copy()

print("Distinct target names:", targets["Service Name"].nunique())
print("First request:", targets["Date and Time"].min())
print("Last request:", targets["Date and Time"].max())
print(
    "Burst duration (seconds):",
    (
        targets["Date and Time"].max()
        - targets["Date and Time"].min()
    ).total_seconds()
)

print("\nRequests by second:")
print(
    targets.groupby(
        targets["Date and Time"].dt.floor("s")
    ).size().to_string()
)

print("\nEncryption types:")
print(
    targets["Ticket Encryption Type"]
    .value_counts(dropna=False)
    .to_string()
)


# Build a timeline for the suspicious source IP

source_ip = "10.30.24.249"

related = df[
    df.astype(str).apply(
        lambda col: col.str.contains(
            source_ip, regex=False, na=False
        )
    ).any(axis=1)
].copy()

related["Date and Time"] = pd.to_datetime(
    related["Date and Time"], errors="coerce"
)

related = related.sort_values("Date and Time")

print(
    related[
        [
            "Date and Time",
            "Event ID",
            "Account Name",
            "Source Network Address",
            "Service Name",
            "Logon Type",
            "Logon ID",
        ]
    ].to_string(index=False)
)


# Inspect the complete Event ID 4662 records

directory_access = df[
    df["Event ID"].astype(str).str.strip() == "4662"
].copy()

print("4662 events:", len(directory_access))

for col in directory_access.columns:
    if directory_access[col].notna().any():
        print(f"\n--- {col} ---")
        print(directory_access[col].dropna().to_string(index=False))


# Display every column for the two directory-access events

events_4662 = df[
    df["Event ID"].astype(str).str.strip() == "4662"
]

for index, row in events_4662.iterrows():
    print(f"\n{'=' * 20} Event row {index} {'=' * 20}")

    for column, value in row.items():
        if pd.notna(value):
            print(f"{column}: {value}")


# Inspect sfadmin activity and nearby authentication events

window = df.copy()
window["Date and Time"] = pd.to_datetime(
    window["Date and Time"], errors="coerce"
)

start = pd.Timestamp("2025-01-19 15:20:00")
end = pd.Timestamp("2025-01-19 15:26:00")

focus = window[
    window["Date and Time"].between(start, end)
    & (
        window["Account Name"].astype(str).str.contains(
            r"sfadmin|RonTestUser42|RM-ESX-IS22-1\$|RM-ESX-DC22-1\$",
            case=False,
            regex=True,
            na=False,
        )
        | window["Event ID"].astype(str).str.strip().isin(
            ["4624", "4625", "4672", "4634", "4768", "4769", "4662"]
        )
    )
].sort_values("Date and Time")

print(focus.to_string(index=False))


# Inspect security-relevant events involving sfadmin

events = df.copy()
events["Date and Time"] = pd.to_datetime(
    events["Date and Time"], errors="coerce"
)

start = pd.Timestamp("2025-01-19 15:20:00")
end = pd.Timestamp("2025-01-19 15:35:00")

account_col = events["Account Name"].astype(str)

sfadmin_events = events[
    events["Date and Time"].between(start, end)
    & account_col.str.contains(
        "sfadmin", case=False, na=False
    )
]

print("sfadmin events:", len(sfadmin_events))

for _, row in sfadmin_events.iterrows():
    print("\n---", row["Date and Time"], "---")
    for col in [
        "Event ID",
        "Task Category",
        "Account Name",
        "Source Network Address",
        "Service Name",
        "Object Name",
        "Accesses",
        "Logon ID",
        "Process Name",
    ]:
        if col in row.index and pd.notna(row[col]):
            print(f"{col}: {row[col]}")

# Show all events from the suspicious source IP
source_ip = "10.30.24.249"

source_events = events[
    events["Source Network Address"].astype(str)
    .str.contains(source_ip, na=False)
].sort_values("Date and Time")

print("Events from source:", len(source_events))

cols = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Source Network Address",
    "Service Name",
    "Logon ID",
    "Process Name"
]

print(source_events[
    [c for c in cols if c in source_events.columns]
].to_string(index=False))

target_ids = [
    "0x34BF4BCC",
    "0x34BF47CB",
    "0x34BF466B",
    "0x34BF4643",
    "0x34BF461F"
]

session_events = events[
    events["Logon ID"].astype(str).isin(target_ids)
].sort_values("Date and Time")

cols = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Logon ID",
    "Task Category",
    "Object Name",
    "Object Type",
    "Accesses",
    "Process Name"
]

print(session_events[
    [c for c in cols if c in session_events.columns]
].to_string(index=False))

events_4662 = events[
    (events["Event ID"].astype(str) == "4662")
    & (events["Logon ID"].astype(str).str.lower() == "0x34bf461f")
]

for _, row in events_4662.iterrows():
    print("\n" + "=" * 60)
    for col, value in row.items():
        if pd.notna(value):
            print(f"{col}: {value}")

privilege_events = events[
    events["Event ID"].astype(str) == "4672"
].copy()

for _, row in privilege_events.iterrows():
    account = str(row.get("Account Name", ""))

    if account.lower() in ["rontestuser42", "sfadmin"]:
        print("\n" + "=" * 50)

        for col, value in row.items():
            if pd.notna(value):
                print(f"{col}: {value}")

source_ip = "10.30.24.249"

source_events = events[
    events.astype(str)
    .apply(lambda col: col.str.contains(source_ip, regex=False, na=False))
    .any(axis=1)
].sort_values("Date and Time")

print("Total events mentioning source IP:", len(source_events))

for _, row in source_events.iterrows():
    print(
        row.get("Date and Time"),
        "| Event:", row.get("Event ID"),
        "| Account:", row.get("Account Name"),
        "| Category:", row.get("Task Category")
    )
# Review the 100 RonTestUser service-ticket requests
ticket_events = events[
    (events["Event ID"].astype(str) == "4769")
    & events["Account Name"].astype(str).str.contains(
        "rm_user", case=False, na=False
    )
]

targets = ticket_events[
    ticket_events["Service Name"].astype(str).str.match(
        r"RonTestUser\d+$", case=False, na=False
    )
].copy()

print("Matching ticket requests:", len(targets))
print("\nTarget accounts:")
print(sorted(targets["Service Name"].dropna().unique()))

print("\nAvailable columns:")
print(targets.columns.tolist())

# Summarise the 100 matching service-ticket requests
print("Ticket encryption types:")
print(targets["Ticket Encryption Type"].value_counts(dropna=False))

print("\nSession encryption types:")
print(targets["Session Encryption Type"].value_counts(dropna=False))

print("\nService IDs:")
print(targets["Service ID"].value_counts(dropna=False).head(20))

print("\nClient addresses:")
print(targets["Client Address"].value_counts(dropna=False))

print("\nFailure codes:")
print(targets["Failure Code"].value_counts(dropna=False))

print("\nUnique target count:",
      targets["Service Name"].nunique())

# Show Kerberos events for RonTestUser42
ron42 = events[
    events["Account Name"].astype(str).str.contains(
        "RonTestUser42", case=False, na=False
    )
    & events["Event ID"].astype(str).isin(["4768", "4769", "4771"])
].sort_values("Date and Time")

cols = [
    "Date and Time",
    "Event ID",
    "Account Name",
    "Service Name",
    "Service ID",
    "Client Address",
    "Ticket Encryption Type",
    "Failure Code"
]

print(ron42[
    [c for c in cols if c in ron42.columns]
].to_string(index=False))
