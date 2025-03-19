# Brute-Force Detection in Azure Activity with KQL

This project uses KQL to detect potential brute-force activity in AzureActivity logs, identifying high-frequency callers and analyzing full records.

## Brute-Force Results
- **Date:** March 17, 2025
- **Findings:** Returned 9 instances of potential brute-force activity in 24 hours. Top record:
  - `TotalAttempts`: 210
  - `FailedAttempts`: 200
  - **Analysis:** Suggests an aggressive internal attack with 10 successful logins.

## Visualizations
![Brute-Force Attempts Bar Chart](/brute-force-chart.png)
Bar chart of failed login attempts by user, highlighting a peak of 200 fails from one incident (March 17, 2025).
## Query
```kql
let HighActivityCallers = AzureActivity
| summarize CallCount = count() by Caller, bin(TimeGenerated, 1h)
| where CallCount > 10;
AzureActivity
| join kind=inner HighActivityCallers on Caller, TimeGenerated
| project Caller, TimeGenerated, OperationName, Resource, CallerIpAddress, ResultType, Level, CallCount
| order by CallCount desc, TimeGenerated asc
