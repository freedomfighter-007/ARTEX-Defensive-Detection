# ARTEX SIEM Detection Queries
# Top 10 SIEM Providers — Native Query Formats
# Based on code-derived fingerprints (User-Agents, ports, titles, proxy auth)
# Test and tune for your environment before deploying as alerts.

## 1. Splunk
```spl
# User-Agent detection
index=web OR index=proxy OR index=http
(user_agent="*artex-update-check*" OR user_agent="*artex-pace*" OR user_agent="*artex-enrich/*" OR user_agent="*norma/0.4*")
| stats count by src_ip, dest_ip, user_agent, uri
| where count > 5

# Console title in response
index=web response_body="*Autonomous Penetration Testing Console*"
| table _time, src_ip, dest_ip, status, uri

# Default ports
index=firewall OR index=netflow dest_port IN (8787, 8788)
| stats count by src_ip, dest_ip, dest_port
```

## 2. Microsoft Sentinel (KQL)
```kusto
// User-Agent detection
CommonSecurityLog
| where DeviceVendor == "web" or DeviceProduct contains "proxy"
| where RequestClientApplication contains "artex-update-check"
    or RequestClientApplication contains "artex-pace"
    or RequestClientApplication contains "artex-enrich/"
    or RequestClientApplication contains "norma/0.4"
| summarize count() by SourceIP, DestinationIP, RequestClientApplication

// Console title
CommonSecurityLog
| where AdditionalFields contains "Autonomous Penetration Testing Console"
| project TimeGenerated, SourceIP, DestinationIP, RequestURL

// Ports
CommonSecurityLog
| where DestinationPort in (8787, 8788)
| summarize count() by SourceIP, DestinationIP, DestinationPort
```

## 3. Elastic SIEM / Elasticsearch (EQL / KQL)
```eql
// User-Agent
http where http.request.headers.user-agent : ("*artex-update-check*", "*artex-pace*", "*artex-enrich/*", "*norma/0.4*")

// Title
http where http.response.body.content : "*Autonomous Penetration Testing Console*"

// Ports
network where destination.port in (8787, 8788)
```

## 4. IBM QRadar (AQL)
```aql
SELECT sourceip, destinationip, "User Agent"
FROM events
WHERE "User Agent" ILIKE '%artex-update-check%'
   OR "User Agent" ILIKE '%artex-pace%'
   OR "User Agent" ILIKE '%artex-enrich/%'
   OR "User Agent" ILIKE '%norma/0.4%'
GROUP BY sourceip
LAST 24 HOURS

SELECT sourceip, destinationip, destinationport
FROM events
WHERE destinationport IN (8787, 8788)
```

## 5. Google Chronicle (YARA-L / UDM)
```yara
rule artex_user_agent {
  meta:
    description = "ARTEX User-Agent"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.http.user_agent = /artex-(update-check|pace|enrich)/ or
    $e.network.http.user_agent = /norma\/0\.4/
  condition:
    $e
}
```

## 6. Sumo Logic
```sumo
_sourceCategory=web OR _sourceCategory=proxy
(user_agent=*artex-update-check* OR user_agent=*artex-pace* OR user_agent=*artex-enrich/* OR user_agent=*norma/0.4*)
| count by src_ip, dest_ip, user_agent

_sourceCategory=firewall
dest_port in (8787, 8788)
| count by src_ip, dest_ip, dest_port
```

## 7. LogRhythm
```logrhythm
UserAgent contains "artex-update-check" OR
UserAgent contains "artex-pace" OR
UserAgent contains "artex-enrich/" OR
UserAgent contains "norma/0.4"

DestinationPort = 8787 OR DestinationPort = 8788
```

## 8. ArcSight (CEF / query)
```arcsight
deviceCustomString1 contains "artex-update-check" OR
deviceCustomString1 contains "artex-pace" OR
deviceCustomString1 contains "norma/0.4"

destinationPort IN (8787, 8788)
```

## 9. Securonix
```securonix
useragent like '%artex-update-check%' OR
useragent like '%artex-pace%' OR
useragent like '%artex-enrich/%' OR
useragent like '%norma/0.4%'

destinationport in (8787, 8788)
```

## 10. CrowdStrike Falcon LogScale / Rapid7
```logscale
#user_agent=*artex-update-check* OR #user_agent=*artex-pace* OR #user_agent=*artex-enrich/* OR #user_agent=*norma/0.4*
| groupBy([src_ip, user_agent])

dest_port=8787 OR dest_port=8788
| groupBy([src_ip, dest_port])
```

## Correlation Recommendations (all platforms)
- Combine User-Agent hits with destination port 8787/8788
- Alert on high request rates (>50/min) from a single source matching any ARTEX indicator
- Cross-reference with known ARTEX naming patterns in accounts/files (artex*, pentest-*, zz*)
- Exclude known authorized testing ranges
