# Brute-Force Detection in Azure Activity with KQL

This project uses KQL to detect potential brute-force activity in AzureActivity logs, identifying high-frequency callers and analyzing full records.

## Query
```kql
let HighActivityCallers = AzureActivity
| summarize CallCount = count() by Caller, bin(TimeGenerated, 1h)
| where CallCount > 10;
AzureActivity
| join kind=inner HighActivityCallers on Caller, TimeGenerated
| project Caller, TimeGenerated, OperationName, Resource, CallerIpAddress, ResultType, Level, CallCount
| order by CallCount desc, TimeGenerated asc
