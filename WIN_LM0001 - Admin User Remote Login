## WIN_LM0001 - Admin User Remote Logon

Description
> Detect remote login by Administrator user depending on internal pattern

Information Domain: Host
Analytic Type: Situational Awareness
Targeted OS: Windows
Tactic: Lateral Movement
Technique: T1078 Valid Accounts
Data Source: Windows Event Logs
Logging Policy:
Status: 
Confidence:
Reference: https://car.mitre.org/analytics/CAR-2016-04-005

## Analytic Usage

Describe how you use this analytic.  Include hunting techniques like searching, clustering, grouping, stacking counting, graphing, etc... 

Any issues that may occur, like high false postives.

Identify any time or data amount required for the analytic to be effective.


### SIGMA
```
title: Admin User Remote Logon
description: Detect remote login by Administrator user depending on internal pattern
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
tags:
    - attack.lateral_movement
    - attack.t1078
status: experimental
author: juju4
logsource:
    product: windows
    service: security
    definition: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
detection:
    selection:
        EventID: 4624
        LogonType: 10
        AuthenticationPackageName: Negotiate
        AccountName: 'Admin-*'
    condition: selection
falsepositives: 
    - Legitimate administrative activity
level: low
```

### Splunk
```
(EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*")
```

### Kibana
```
[
  {
    "_id": "Admin-User-Remote-Logon",
    "_type": "search",
    "_source": {
      "title": "Sigma: Admin User Remote Logon",
      "description": "Detect remote login by Administrator user depending on internal pattern",
      "hits": 0,
      "columns": [],
      "sort": [
        "@timestamp",
        "desc"
      ],
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\": \"*\", \"filter\": [], \"highlight\": {\"pre_tags\": [\"@kibana-highlighted-field@\"], \"post_tags\": [\"@/kibana-highlighted-field@\"], \"fields\": {\"*\": {}}, \"require_field_match\": false, \"fragment_size\": 2147483647}, \"query\": {\"query_string\": {\"query\": \"(EventID:\\\"4624\\\" AND LogonType:\\\"10\\\" AND AuthenticationPackageName:\\\"Negotiate\\\" AND AccountName:\\\"Admin\\\\-*\\\")\", \"analyze_wildcard\": true}}}"
      }
    }
  }
]
```

### Trigger for testing

Add link to Atomic Red Team or other testing mechanism.

 