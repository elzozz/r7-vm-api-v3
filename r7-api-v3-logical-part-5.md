## Vulnerability Exception
Vulnerability Exception Resource Controller

### /api/3/vulnerability_exceptions

#### GET
##### Summary

Exceptions

##### Description

Returns all exceptions defined on vulnerabilities.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityException%C2%BB](#pageof%c2%abvulnerabilityexception%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Exceptions

##### Description

Creates a vulnerability exception.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| vulnerabilityException | body | The vulnerability exception to create. | No | [VulnerabilityException](#vulnerabilityexception) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABVulnerabilityExceptionID,Link%C2%BB](#createdreference%c2%abvulnerabilityexceptionid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_exceptions/{id}

#### GET
##### Summary

Exception

##### Description

Returns an exception made on a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability exception. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityException](#vulnerabilityexception) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Exception

##### Description

Removes an exception made on a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | id | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_exceptions/{id}/expires

#### GET
##### Summary

Exception Expiration

##### Description

Get the expiration date for a vulnerability exception.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | id | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | string |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Exception Expiration

##### Description

Set the expiration date for a vulnerability exception. This must be a valid date in the future.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | id | Yes | integer |
| param1 | body | param1 | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_exceptions/{id}/{status}

#### POST
##### Summary

Exception Status

##### Description

Update the status of the vulnerability exception. The status can be one of: `"recall"`, `"approve"`, or `"reject"`.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | id | Yes | integer |
| status | path | Exception Status | Yes | string |
| param2 | body | param2 | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
### Models

#### Account

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| service | string |  | No |

#### AdditionalInformation

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| html | string | Hypertext Markup Language (HTML) representation of the content.<br>*Example:* `""` | No |
| text | string | Textual representation of the content.<br>*Example:* `""` | No |

#### Address

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| ip | string | The IPv4 or IPv6 address.<br>*Example:* `"123.245.34.235"` | No |
| mac | string | The Media Access Control (MAC) address. The format is six groups of two hexadecimal digits separated by colons.<br>*Example:* `"12:34:56:78:90:AB"` | No |

#### AdhocScan

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assetGroupIds | [ integer ] | The asset groups that should be included as a part of the scan. Only asset groups assigned to the site can be specified for a scan. This value should be an array of integers representing the unique identifiers of the asset groups. | No |
| engineId | integer | The identifier of the scan engine.<br>*Example:* `""` | No |
| hosts | [ string ] | The hosts that should be included as a part of the scan. This should be a mixture of IP Addresses and Hostnames as a String array. | No |
| name | string | The user-driven scan name for the scan.<br>*Example:* `""` | No |
| templateId | string | The identifier of the scan template<br>*Example:* `""` | No |

#### AdvisoryLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| href | string | The hypertext reference for the vulnerability reference.<br>*Example:* `"https://support.microsoft.com/en-us/kb/4041689"` | No |
| rel | string | The relation of the hypermedia link, `"Advisory"`.<br>*Example:* `"Advisory"` | No |

#### Agent

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ [Address](#address) ] | All addresses discovered on the asset. | No |
| agentId | string | The identifier of the agent.<br>*Example:* `"fe1708451f8c78c3a20a8a79818878e1"` | No |
| assessedForPolicies | boolean | Whether the asset has been assessed for policies at least once.<br>*Example:* `false` | No |
| assessedForVulnerabilities | boolean | Whether the asset has been assessed for vulnerabilities at least once.<br>*Example:* `true` | No |
| configurations | [ [Configuration](#configuration) ] | Configuration key-values pairs enumerated on the asset. | No |
| databases | [ [Database](#database) ] | The databases enumerated on the asset. | No |
| files | [ [File](#file) ] | The files discovered with searching on the asset. | No |
| history | [ [AssetHistory](#assethistory) ] | The history of changes to the asset over time. | No |
| hostName | string | The primary host name (local or FQDN) of the asset.<br>*Example:* `"corporate-workstation-1102DC.acme.com"` | No |
| hostNames | [ [HostName](#hostname) ] | All host names or aliases discovered on the asset. | No |
| id | long | The identifier of the asset.<br>*Example:* `282` | No |
| ids | [ [UniqueId](#uniqueid) ] | Unique identifiers found on the asset, such as hardware or operating system identifiers. | No |
| ip | string | The primary IPv4 or IPv6 address of the asset.<br>*Example:* `"182.34.74.202"` | No |
| lastAssessedForVulnerabilities | string | The time the last vulnerability assessment occured.<br>*Example:* `"2019-09-11T10:39:51.288Z"` | Yes |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| mac | string | The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.<br>*Example:* `"AB:12:CD:34:EF:56"` | No |
| os | string | The full description of the operating system of the asset.<br>*Example:* `"Microsoft Windows Server 2008 Enterprise Edition SP1"` | No |
| osCertainty | string | ${asset.os.certainty}<br>*Example:* `"0.75"` | No |
| osFingerprint | [OperatingSystem](#operatingsystem) | The details of the operating system of the asset.<br>*Example:* `""` | No |
| rawRiskScore | double | The base risk score of the asset.<br>*Example:* `31214.3` | No |
| riskScore | double | The risk score (with criticality adjustments) of the asset.<br>*Example:* `37457.16` | No |
| services | [ [Service](#service) ] | The services discovered on the asset. | No |
| software | [ [Software](#software) ] | The software discovered on the asset. | No |
| type | string | The type of asset.<br>*Enum:* `"unknown"`, `"guest"`, `"hypervisor"`, `"physical"`, `"mobile"`<br>*Example:* `""` | No |
| userGroups | [ [GroupAccount](#groupaccount) ] | The group accounts enumerated on the asset. | No |
| users | [ [UserAccount](#useraccount) ] | The user accounts enumerated on the asset. | No |
| vulnerabilities | [AssetVulnerabilities](#assetvulnerabilities) | Summary information for vulnerabilities on the asset.<br>*Example:* `""` | No |

#### Alert

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| enabled | boolean | Flag indicating the alert is enabled.<br>*Example:* `false` | Yes |
| enabledScanEvents | [ScanEvents](#scanevents) | Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.<br>*Example:* `""` | No |
| enabledVulnerabilityEvents | [VulnerabilityEvents](#vulnerabilityevents) | Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.<br>*Example:* `""` | No |
| id | integer | The identifier of the alert.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| maximumAlerts | integer | The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.<br>*Example:* `""` | No |
| name | string | The name of the alert.<br>*Example:* `""` | Yes |
| notification | string | The type of alert.<br>*Enum:* `"SMTP"`, `"SNMP"`, `"Syslog"`<br>*Example:* `""` | Yes |

#### AssessmentResult

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| checkId | string | The identifier of the vulnerability check.<br>*Example:* `"ssh-openssh-x11uselocalhost-x11-forwarding-session-hijack"` | No |
| exceptions | [ integer ] | If the result is vulnerable with exceptions applied, the identifier(s) of the exceptions actively applied to the result. | No |
| key | string | An additional discriminating key used to uniquely identify between multiple instances of results on the same finding.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| port | integer | The port of the service the result was discovered on.<br>*Example:* `22` | No |
| proof | string | The proof explaining why the result was found vulnerable. The proof may container embedded HTML formatting markup.<br>*Example:* `"<p><p>OpenBSD OpenSSH 4.3 on Linux</p></p>"` | No |
| protocol | string | The protocol of the service the result was discovered on.<br>*Enum:* `"ip"`, `"icmp"`, `"igmp"`, `"ggp"`, `"tcp"`, `"pup"`, `"udp"`, `"idp"`, `"esp"`, `"nd"`, `"raw"`<br>*Example:* `"tcp"` | No |
| since | string | The date and time the result was first recorded, in the ISO8601 format. If the result changes status this value is the date and time of the status change.<br>*Example:* `"2017-08-09T11:32:33.658Z"` | No |
| status | string | The status of the vulnerability check result.<br>*Enum:* `"unknown"`, `"not-vulnerable"`, `"vulnerable"`, `"vulnerable-version"`, `"vulnerable-potential"`, `"vulnerable-with-exception-applied"`, `"vulnerable-version-with-exception-applied"`, `"vulnerable-potential-with-exception-applied"`<br>*Example:* `"vulnerable-version"` | Yes |

#### Asset

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ [Address](#address) ] | All addresses discovered on the asset. | No |
| assessedForPolicies | boolean | Whether the asset has been assessed for policies at least once.<br>*Example:* `false` | No |
| assessedForVulnerabilities | boolean | Whether the asset has been assessed for vulnerabilities at least once.<br>*Example:* `true` | No |
| configurations | [ [Configuration](#configuration) ] | Configuration key-values pairs enumerated on the asset. | No |
| databases | [ [Database](#database) ] | The databases enumerated on the asset. | No |
| files | [ [File](#file) ] | The files discovered with searching on the asset. | No |
| history | [ [AssetHistory](#assethistory) ] | The history of changes to the asset over time. | No |
| hostName | string | The primary host name (local or FQDN) of the asset.<br>*Example:* `"corporate-workstation-1102DC.acme.com"` | No |
| hostNames | [ [HostName](#hostname) ] | All host names or aliases discovered on the asset. | No |
| id | long | The identifier of the asset.<br>*Example:* `282` | No |
| ids | [ [UniqueId](#uniqueid) ] | Unique identifiers found on the asset, such as hardware or operating system identifiers. | No |
| ip | string | The primary IPv4 or IPv6 address of the asset.<br>*Example:* `"182.34.74.202"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| mac | string | The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.<br>*Example:* `"AB:12:CD:34:EF:56"` | No |
| os | string | The full description of the operating system of the asset.<br>*Example:* `"Microsoft Windows Server 2008 Enterprise Edition SP1"` | No |
| osCertainty | string | ${asset.os.certainty}<br>*Example:* `"0.75"` | No |
| osFingerprint | [OperatingSystem](#operatingsystem) | The details of the operating system of the asset.<br>*Example:* `""` | No |
| rawRiskScore | double | The base risk score of the asset.<br>*Example:* `31214.3` | No |
| riskScore | double | The risk score (with criticality adjustments) of the asset.<br>*Example:* `37457.16` | No |
| services | [ [Service](#service) ] | The services discovered on the asset. | No |
| software | [ [Software](#software) ] | The software discovered on the asset. | No |
| type | string | The type of asset.<br>*Enum:* `"unknown"`, `"guest"`, `"hypervisor"`, `"physical"`, `"mobile"`<br>*Example:* `""` | No |
| userGroups | [ [GroupAccount](#groupaccount) ] | The group accounts enumerated on the asset. | No |
| users | [ [UserAccount](#useraccount) ] | The user accounts enumerated on the asset. | No |
| vulnerabilities | [AssetVulnerabilities](#assetvulnerabilities) | Summary information for vulnerabilities on the asset.<br>*Example:* `""` | No |

#### AssetCreate

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ [Address](#address) ] | All addresses discovered on the asset. | No |
| assessedForPolicies | boolean | Whether the asset has been assessed for policies at least once.<br>*Example:* `false` | No |
| assessedForVulnerabilities | boolean | Whether the asset has been assessed for vulnerabilities at least once.<br>*Example:* `true` | No |
| configurations | [ [Configuration](#configuration) ] | Configuration key-values pairs enumerated on the asset. | No |
| cpe | string | The Common Platform Enumeration (CPE) of the operating system. This is the tertiary means of specifying the operating system fingerprint. Use `"osFingerprint"` or `"os"` as a more accurate means of defining the operating system.<br>*Example:* `""` | No |
| databases | [ [Database](#database) ] | The databases enumerated on the asset. | No |
| date | string | The date the data was collected on the asset.<br>*Example:* `""` | Yes |
| description | string | The description of the source or collection of information on the asset. This description will appear in the history of the asset for future auditing purposes.<br>*Example:* `""` | No |
| files | [ [File](#file) ] | The files discovered with searching on the asset. | No |
| history | [ [AssetHistory](#assethistory) ] | The history of changes to the asset over time. | No |
| hostName | [HostName](#hostname) | The primary host name (local or FQDN) of the asset.<br>*Example:* `"corporate-workstation-1102DC.acme.com"` | No |
| hostNames | [ [HostName](#hostname) ] | Additional host names for the asset. | No |
| id | long | The identifier of the asset.<br>*Example:* `282` | No |
| ids | [ [UniqueId](#uniqueid) ] | Unique identifiers found on the asset, such as hardware or operating system identifiers. | No |
| ip | string | The primary IPv4 or IPv6 address of the asset.<br>*Example:* `"182.34.74.202"` | No |
| links | [ [Link](#link) ] |  | No |
| mac | string | The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.<br>*Example:* `"AB:12:CD:34:EF:56"` | No |
| os | string | Free-form textual description of the operating system of the asset, typically from a fingerprinting source. This input will be parsed to produce a full fingerprint. This is the secondary means of specifying the operating system. Use `osFingerprint` for a more accurate definition.<br>*Example:* `""` | No |
| osCertainty | string | ${asset.os.certainty.write}<br>*Example:* `""` | No |
| osFingerprint | [OperatingSystem](#operatingsystem) | The details of the operating system of the asset. At least one of `vendor`, `family`, or `product` must be supplied. This is the preferred means of defining the operating system.<br>*Example:* `""` | No |
| rawRiskScore | double | The base risk score of the asset.<br>*Example:* `31214.3` | No |
| riskScore | double | The risk score (with criticality adjustments) of the asset.<br>*Example:* `37457.16` | No |
| services | [ [Service](#service) ] | The services discovered on the asset. | No |
| software | [ [Software](#software) ] | The software discovered on the asset. | No |
| type | string | The type of asset.<br>*Example:* `""` | No |
| userGroups | [ [GroupAccount](#groupaccount) ] | The group accounts enumerated on the asset. | No |
| users | [ [UserAccount](#useraccount) ] | The user accounts enumerated on the asset. | No |
| vulnerabilities | [AssetVulnerabilities](#assetvulnerabilities) | Summary information for vulnerabilities on the asset.<br>*Example:* `""` | No |

#### AssetCreatedOrUpdatedReference

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| body | [ReferenceWith%C2%ABAssetID,Link%C2%BB](#referencewith%c2%abassetid,link%c2%bb) |  | No |
| statusCode | string | *Enum:* `"100"`, `"101"`, `"102"`, `"103"`, `"200"`, `"201"`, `"202"`, `"203"`, `"204"`, `"205"`, `"206"`, `"207"`, `"208"`, `"226"`, `"300"`, `"301"`, `"302"`, `"303"`, `"304"`, `"305"`, `"307"`, `"308"`, `"400"`, `"401"`, `"402"`, `"403"`, `"404"`, `"405"`, `"406"`, `"407"`, `"408"`, `"409"`, `"410"`, `"411"`, `"412"`, `"413"`, `"414"`, `"415"`, `"416"`, `"417"`, `"418"`, `"419"`, `"420"`, `"421"`, `"422"`, `"423"`, `"424"`, `"426"`, `"428"`, `"429"`, `"431"`, `"500"`, `"501"`, `"502"`, `"503"`, `"504"`, `"505"`, `"506"`, `"507"`, `"508"`, `"509"`, `"510"`, `"511"` | No |

#### AssetGroup

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | integer | The number of assets that belong to the asset group.<br>*Example:* `768` | No |
| description | string | The description of the asset group.<br>*Example:* `"Assets with unacceptable high risk required immediate remediation."` | No |
| id | integer | The identifier of the asset group.<br>*Example:* `61` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the asset group.<br>*Example:* `"High Risk Assets"` | Yes |
| riskScore | double | The total risk score of all assets that belong to the asset group.<br>*Example:* `4457823.78` | No |
| searchCriteria | [SearchCriteria](#searchcriteria) | Search criteria used to determine dynamic membership, if `type` is `"dynamic"`. <br>*Example:* `""` | No |
| type | string | The type of the asset group.<br>*Enum:* `"static"`, `"dynamic"`<br>*Example:* `"dynamic"` | Yes |
| vulnerabilities | [Vulnerabilities](#vulnerabilities) | Summary information for distinct vulnerabilities found on the assets.<br>*Example:* `""` | No |

#### AssetHistory

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| date | string | The date the asset information was collected or changed.<br>*Example:* `"2018-04-09T06:23:49Z"` | No |
| description | string | Additional information describing the change.<br>*Example:* `""` | No |
| scanId | long | If a scan-oriented change, the identifier of the corresponding scan the asset was scanned in.<br>*Example:* `12` | No |
| type | string | The type of change. May be one of:  \| Type                                \| Source of Data                                              \|  \| ----------------------------------- \| ----------------------------------------------------------- \|  \| `ASSET-IMPORT`, `EXTERNAL-IMPORT`   \| External source such as the API                             \|  \| `EXTERNAL-IMPORT-APPSPIDER`         \| Rapid7 InsightAppSec (previously known as AppSpider)        \|  \| `SCAN`                              \| Scan engine scan                                            \|  \| `AGENT-IMPORT`                      \| Rapid7 Insight Agent                                        \|  \| `ACTIVE-SYNC`                       \| ActiveSync                                                  \|  \| `SCAN-LOG-IMPORT`                   \| Manual import of a scan log                                 \|  \| `VULNERABILITY_EXCEPTION_APPLIED`   \| Vulnerability exception applied                             \|  \| `VULNERABILITY_EXCEPTION_UNAPPLIED` \| Vulnerability exception unapplied                           \|<br>*Example:* `"SCAN"` | No |
| user | string | If a vulnerability exception change, the login name of the user that performed the operation.<br>*Example:* `""` | No |
| version | integer | The version number of the change (a chronological incrementing number starting from 1). <br>*Example:* `8` | No |
| vulnerabilityExceptionId | integer | If a vulnerability exception change, the identifier of the vulnerability exception that caused the change.<br>*Example:* `""` | No |

#### AssetPolicy

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| benchmarkName | string | The name of the policy's benchmark.<br>*Example:* `""` | No |
| benchmarkVersion | string | The version number of the benchmark that includes the policy.<br>*Example:* `""` | No |
| category | string | A grouping of similar benchmarks based on their source, purpose, or other criteria. Examples include FDCC, USGCB, and CIS.<br>*Example:* `""` | No |
| description | string | The description of the policy.<br>*Example:* `""` | No |
| failedAssetsCount | integer | The number of assets that are not compliant with the policy. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| failedRulesCount | integer | The number of rules in the policy that are not compliant with any scanned assets. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| id | string | The textual representation of the policy identifier.<br>*Example:* `""` | No |
| isCustom | boolean | A flag indicating whether the policy is custom.<br>*Example:* `false` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| notApplicableAssetsCount | integer | The number of assets that were attempted to be scanned, but are not applicable to the policy. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| notApplicableRulesCount | integer | The number of rules in the policy that are not applicable with any scanned assets. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| passedAssetsCount | integer | The number of assets that are compliant with the policy. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| passedRulesCount | integer | The number of rules in the policy that are compliant with all scanned assets. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |
| policyName | string | The name of the policy.<br>*Example:* `""` | No |
| ruleCompliance | double | The ratio of PASS results for the rules to the total number of rules in each policy.<br>*Example:* `""` | No |
| ruleComplianceDelta | double | The change in rule compliance between the last two scans of all assets. The list of scanned policies is based on the user's list of accessible assets.<br>*Example:* `""` | No |
| scope | string | The textual representation of the policy scope. Policies that are automatically available have `"Built-in"` scope, whereas policies created by users have scope as `"Custom"`.<br>*Example:* `""` | No |
| status | string | The overall compliance status of the policy.<br>*Enum:* `"PASS"`, `"FAIL"`, `"NOT_APPLICABLE"`<br>*Example:* `""` | No |
| surrogateId | long | The identifier of the policy<br>*Example:* `""` | No |
| title | string | The title of the policy as visible to the user.<br>*Example:* `""` | No |
| unscoredRules | integer | The number of rules defined in the policy with a role of "unscored". These rules will not affect rule compliance scoring for the policy.<br>*Example:* `""` | No |

#### AssetPolicyAssessment

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| total | integer | The total number of assets.<br>*Example:* `""` | No |
| totalFailed | integer | The total number of assets that are not compliant.<br>*Example:* `""` | No |
| totalNotApplicable | integer | The total number of assets that are not applicable.<br>*Example:* `""` | No |
| totalPassed | integer |  | No |

#### AssetPolicyItem

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [AssetPolicyAssessment](#assetpolicyassessment) | A summary of asset compliance.<br>*Example:* `""` | No |
| description | string | A description of the policy rule or group.<br>*Example:* `""` | No |
| hasOverride | boolean | A flag indicating whether the policy rule has an active override applied to it. This field only applies to resources representing policy rules. <br>*Example:* `false` | No |
| id | long | The identifier of the policy rule or group.<br>*Example:* `""` | No |
| isUnscored | boolean | A flag indicating whether the policy rule has a role of `"unscored"`. This field only applies to resources representing policy rules.<br>*Example:* `false` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the policy rule or group.<br>*Example:* `""` | No |
| policy | [PolicyMetadataResource](#policymetadataresource) | Information about the policy.<br>*Example:* `""` | No |
| rules | [PolicyRuleAssessmentResource](#policyruleassessmentresource) | A summary of rule compliance for multiple policy rules. This field only applies to resources representing policy groups.<br>*Example:* `""` | No |
| scope | string | The textual representation of the policy rule/group scope. Policy rules or groups that are automatically available have `"Built-in"` scope, whereas policy rules or groups created by users have scope as `"Custom"`.<br>*Example:* `""` | No |
| status | string | The asset's rule compliance status.<br>*Enum:* `"PASS"`, `"FAIL"`, `"NOT_APPLICABLE"`<br>*Example:* `""` | No |
| title | string | The title of the policy rule, or group, as visible to the user.<br>*Example:* `""` | No |
| type | string | Indicates whether the resource represents either a policy rule or group.<br>*Enum:* `"rule"`, `"group"`<br>*Example:* `""` | No |

#### AssetTag

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| color | string | The color to use when rendering the tag in a user interface.<br>*Enum:* `"default"`, `"blue"`, `"green"`, `"orange"`, `"red"`, `"purple"`<br>*Example:* `"default"` | No |
| created | string | The date and time the tag was created.<br>*Example:* `"2017-10-07T23:50:01.205Z"` | No |
| id | integer | The identifier of the tag.<br>*Example:* `6` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name (label) of the tab.<br>*Example:* `"My Custom Tag"` | Yes |
| riskModifier | object | The amount to adjust risk of an asset tagged with this tag. <br>*Example:* `"2.0"` | No |
| searchCriteria | [SearchCriteria](#searchcriteria) |  | No |
| source | string | The source of the tag.<br>*Enum:* `"built-in"`, `"custom"`<br>*Example:* `"custom"` | No |
| sources | [ [TagAssetSource](#tagassetsource) ] | The source(s) by which a tag is-applied to an asset. | No |
| type | string | The type of the tag.<br>*Enum:* `"custom"`, `"location"`, `"owner"`, `"criticality"`<br>*Example:* `"custom"` | Yes |

#### AssetVulnerabilities

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| critical | long | The number of critical vulnerabilities.<br>*Example:* `16` | No |
| exploits | long | The number of distinct exploits that can exploit any of the vulnerabilities on the asset.<br>*Example:* `4` | No |
| malwareKits | long | The number of distinct malware kits that vulnerabilities on the asset are susceptible to.<br>*Example:* `0` | No |
| moderate | long | The number of moderate vulnerabilities.<br>*Example:* `3` | No |
| severe | long | The number of severe vulnerabilities.<br>*Example:* `76` | No |
| total | long | The total number of vulnerabilities.<br>*Example:* `95` | No |

#### AuthenticationSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| 2fa | boolean | Whether two-factor authentication is enabled.<br>*Example:* `false` | No |
| loginLockThreshold | integer | The maximum number of failed login attempts for an account becomes locked.<br>*Example:* `"true"` | No |

#### AuthenticationSource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| external | boolean | Whether the authentication source is external (true) or internal (false).<br>*Example:* `false` | No |
| id | integer | The identifier of the authentication source.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the authentication source.<br>*Example:* `""` | No |
| type | string | The type of the authentication source.<br>*Enum:* `"normal"`, `"kerberos"`, `"ldap"`, `"saml"`, `"admin"`<br>*Example:* `""` | No |

#### AvailableReportFormat

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| format | string | The output file-format of a report.<br>*Enum:* `"arf-xml"`, `"csv-export"`, `"cyberscope-xml"`, `"pdf"`, `"html"`, `"nexpose-simple-xml"`, `"oval-xml"`, `"qualys-xml"`, `"rtf"`, `"scap-xml"`, `"sql-query"`, `"text"`, `"xccdf-xml"`, `"xccdf-csv"`, `"xml"`, `"xml-export"`, `"xml-export-v2"`<br>*Example:* `"pdf"` | No |
| templates | [ string ] | The report template identifiers that can be used within a report format. | No |

#### BackupsSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `0` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"0 bytes"` | No |

#### BadRequestError

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"400"`<br>*Example:* `"400"` | Yes |

#### CPUInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| clockSpeed | integer | The clock speed of the host, in MHz.<br>*Example:* `2600` | No |
| count | integer | The number of CPUs.<br>*Example:* `8` | No |

#### Configuration

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| name | string | The name of the configuration value.<br>*Example:* `"<name>"` | Yes |
| value | string | The configuration value.<br>*Example:* `"<value>"` | No |

#### ConsoleCommandOutput

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| output | string | The output of the command that was executed.<br>*Example:* `""` | No |

#### ContentDescription

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| html | string | Hypertext Markup Language (HTML) representation of the content.<br>*Example:* `"A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Microsoft Edge. ..."` | No |
| text | string | Textual representation of the content.<br>*Example:* `"<p>A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Microsoft Edge. ...</p>"` | No |

#### CreateAuthenticationSource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the authentication source to use to authenticate the user. The source with the specified identifier must be of the type specified by `type`. If `id` is omitted, then one source of the specified `type` is selected.<br>*Example:* `""` | No |
| type | string | The type of the authentication source to use to authenticate the user.<br>*Example:* `""` | Yes |

#### CreatedOrUpdatedReference

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | object | The identifier of the resource created or updated.<br>*Example:* `"3"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | object | The identifier of the resource created.<br>*Example:* `"1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«AssetGroupID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«CredentialID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«DiscoveryQueryID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«EngineID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«PolicyOverrideID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«ScanID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«ScanTemplateID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | string | The identifier of the resource created.<br>*Example:* `"1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«UserID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«VulnerabilityExceptionID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«VulnerabilityValidationID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### CreatedReference«int,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource created.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### Criterion

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| Criterion | object |  |  |

#### Database

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| description | string | The description of the database instance.<br>*Example:* `"Microsoft SQL Server"` | No |
| id | integer | The identifier of the database.<br>*Example:* `13` | No |
| name | string | The name of the database instance.<br>*Example:* `"MSSQL"` | Yes |

#### DatabaseConnectionSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| maximumAdministrationPoolSize | integer | The maximum number of administrative connections in the connection pool. -1 means unlimited.<br>*Example:* `-1` | No |
| maximumPoolSize | integer | The maximum number of connections in the connection pool. -1 means unlimited.<br>*Example:* `-1` | No |
| maximumPreparedStatementPoolSize | integer | The maximum number of prepared statements in the prepared statement pool. -1 means unlimited.<br>*Example:* `256` | No |

#### DatabaseSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| connection | [DatabaseConnectionSettings](#databaseconnectionsettings) | Details connection settings for the database.<br>*Example:* `""` | No |
| host | string | The database host.<br>*Example:* `"127.0.0.1"` | No |
| maintenanceThreadPoolSize | integer | The maximum number of parallel tasks when executing maintenance tasks.<br>*Example:* `20` | No |
| port | integer | The database port.<br>*Example:* `5432` | No |
| url | string | The database connection URL.<br>*Example:* `"//127.0.0.1:5432/nexpose"` | No |
| user | string | The database user.<br>*Example:* `"nxpgsql"` | No |
| vendor | string | The database vendor.<br>*Example:* `"postgresql"` | No |

#### DatabaseSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `5364047843` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"5 GB"` | No |

#### DiscoveryAsset

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| address | string | The IP address of a discovered asset.<br>*Example:* `"12.83.99.203"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The host name of a discovered asset.<br>*Example:* `"desktop-27.acme.com"` | No |

#### DiscoveryConnection

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| accessKeyId | string | The AWS credential access key identifier (only used for the AWS connection).<br>*Example:* `""` | No |
| address | string | The address used to connect to the discovery connection source.<br>*Example:* `""` | No |
| arn | string | The AWS credential ARN (only used for the AWS connection).<br>*Example:* `""` | No |
| awsSessionName | string | The AWS credential session name (only used for the AWS connection).<br>*Example:* `""` | No |
| connectionType | string | The type of the discovery connection.<br>*Example:* `""` | No |
| eventSource | string | The event source type to use.<br>*Example:* `""` | No |
| exchangeServerHostname | string | The hostname of the exchange server to connect to.<br>*Example:* `""` | No |
| exchangeUser | string | The username used to connect to the exchange server.<br>*Example:* `""` | No |
| folderPath | string | The folder path to pull logs from.<br>*Example:* `""` | No |
| id | long | The identifier of the discovery connection.<br>*Example:* `""` | No |
| ldapServer | string | The LDAP server to connect to.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The discovery connection name.<br>*Example:* `"Connection 1"` | No |
| port | integer | The port used to connect to the discovery connection source.<br>*Example:* `""` | No |
| protocol | string | The protocol used to connect to the discovery connection source.<br>*Example:* `""` | No |
| region | string | The AWS region (only used for the AWS connection).<br>*Example:* `""` | No |
| scanEngineIsInsideAWS | boolean | Flag denoting whether the scan engine is in AWS, this is used for AWS discovery connections for scanning purposes (only used for the AWS connection).<br>*Example:* `false` | No |
| secretAccessKey | string | The AWS credential secret access key (only used for the AWS connection).<br>*Example:* `""` | No |
| status | string | The status of the discovery connection.<br>*Example:* `""` | No |
| username | string | The username used to authenticate to the discovery connection source.<br>*Example:* `""` | No |
| winRMServer | string | The WinRM server to connect to. <br>*Example:* `""` | No |

#### DiscoverySearchCriteria

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| connectionType | string | The type of discovery connection configured for the site. This property only applies to dynamic sites.<br>*Enum:* `"activesync-ldap"`, `"activesync-office365"`, `"activesync-powershell"`, `"aws"`, `"dhcp"`, `"sonar"`, `"vsphere"`<br>*Example:* `""` | No |
| filters | [ [SwaggerDiscoverySearchCriteriaFilter](#swaggerdiscoverysearchcriteriafilter) ] | Filters used to match assets from a discovery connection. See <a href="#section/Responses/DiscoverySearchCriteria">Discovery Connection Search Criteria</a> for more information on the structure and format. | No |
| match | string | Operator to determine how to match filters. `all` requires that all filters match for an asset to be included. `any` requires only one filter to match for an asset to be included.<br>*Enum:* `"any"`, `"all"`<br>*Example:* `"all"` | No |

#### DiskFree

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `166532222976` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"155.1 GB"` | No |

#### DiskInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| free | [DiskFree](#diskfree) | Available disk space.<br>*Example:* `""` | No |
| installation | [InstallSize](#installsize) | Details regarding the size of disk used by the console installation.<br>*Example:* `""` | No |
| total | [DiskTotal](#disktotal) | Total disk space.<br>*Example:* `""` | No |

#### DiskTotal

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `499004735488` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"464.7 GB"` | No |

#### DynamicSite

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the discovery connection.<br>*Example:* `""` | Yes |

#### EngineID

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer |  | No |
| newScanEngine | boolean |  | No |
| scope | string | *Enum:* `"global"`, `"silo"` | No |

#### EnginePool

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| engines | [ integer ] | The identifiers of the scan engines in the engine pool. | No |
| id | integer | The identifier of the scan engine.<br>*Example:* `6` | Yes |
| links | [ [Link](#link) ] |  | No |
| name | string | The name of the scan engine.<br>*Example:* `"Corporate Scan Engine 001"` | Yes |
| sites | [ integer ] | A list of identifiers of each site the scan engine is assigned to. | No |

#### EnvironmentProperties

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| properties | object | Key-value pairs for system and environment properties that are currently defined.<br>*Example:* `""` | No |

#### Error

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"100"`, `"101"`, `"102"`, `"103"`, `"200"`, `"201"`, `"202"`, `"203"`, `"204"`, `"205"`, `"206"`, `"207"`, `"208"`, `"226"`, `"300"`, `"301"`, `"302"`, `"303"`, `"304"`, `"305"`, `"307"`, `"308"`, `"400"`, `"401"`, `"402"`, `"403"`, `"404"`, `"405"`, `"406"`, `"407"`, `"408"`, `"409"`, `"410"`, `"411"`, `"412"`, `"413"`, `"414"`, `"415"`, `"416"`, `"417"`, `"418"`, `"419"`, `"420"`, `"421"`, `"422"`, `"423"`, `"424"`, `"426"`, `"428"`, `"429"`, `"431"`, `"500"`, `"501"`, `"502"`, `"503"`, `"504"`, `"505"`, `"506"`, `"507"`, `"508"`, `"509"`, `"510"`, `"511"`<br>*Example:* `""` | No |

#### ExceptionScope

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the scope type to which the exception applies. For example in a site scoped vulnerability exception this is the site id, in an asset group vulnerability exception this is the asset group id.<br>*Example:* `""` | No |
| key | string | If the scope type is `"Instance"`, an optional key to discriminate the instance the exception applies to.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| port | integer | If the scope type is `"Instance"` and the vulnerability is detected on a service, the port on which the exception applies.<br>*Example:* `""` | No |
| type | string | The type of the exception scope. One of: `"Global"`, `"Site"`, `"Asset"`, `"Asset Group"`, `"Instance"`<br>*Example:* `""` | No |
| vulnerability | string | The identifier of the vulnerability to which the exception applies.<br>*Example:* `""` | No |

#### ExcludedAssetGroups

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assetGroupIDs | [ integer ] | List of asset group identifiers. Each element is an integer. | No |
| links | [ [Link](#link) ] |  | No |

#### ExcludedScanTargets

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ string ] | List of addresses. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No |
| links | [ [Link](#link) ] |  | No |

#### Exploit

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the exploit.<br>*Example:* `4924` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| skillLevel | string | The level of skill required to use the exploit.<br>*Enum:* `"novice"`, `"intermediate"`, `"expert"`<br>*Example:* `"expert"` | No |
| source | [ExploitSource](#exploitsource) | Details about where the exploit is defined.<br>*Example:* `""` | No |
| title | string | The title (short summary) of the exploit.<br>*Example:* `"Microsoft IIS WebDav ScStoragePathFromUrl Overflow"` | No |

#### ExploitSource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| key | string | The identifier of the exploit in the source library.<br>*Example:* `"exploit/windows/iis/iis_webdav_scstoragepathfromurl"` | No |
| link | [ExploitSourceLink](#exploitsourcelink) | Link to the source of the exploit.<br>*Example:* `""` | No |
| name | string | The source library of the exploit, typically the name of the vendor that maintains and/or defined the exploit.<br>*Enum:* `"metasploit"`, `"exploitdb"`<br>*Example:* `"metasploit"` | No |

#### ExploitSourceLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| href | string | The hypertext reference for the exploit source.<br>*Example:* `"http://www.metasploit.com/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl"` | No |
| id | string | Hypermedia link to the destination of the exploit source.<br>*Example:* `"exploit/windows/iis/iis_webdav_scstoragepathfromurl"` | No |
| rel | string | The relation of the hypermedia link, `"Source"`.<br>*Example:* `"Source"` | No |

#### Features

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| adaptiveSecurity | boolean | Whether Adaptive Security features are available.<br>*Example:* `false` | No |
| agents | boolean | Whether the use of agents is allowed.<br>*Example:* `true` | No |
| dynamicDiscovery | boolean | Whether dynamic discovery sources may be used.<br>*Example:* `true` | No |
| earlyAccess | boolean | Whether early-access features are available prior to general availability.<br>*Example:* `false` | No |
| enginePool | boolean | Whether scan engine pools may be used.<br>*Example:* `true` | No |
| insightPlatform | boolean | Whether the usage of the Insight platform is allowed.<br>*Example:* `true` | No |
| mobile | boolean | Whether mobile features are allowed.<br>*Example:* `true` | No |
| multitenancy | boolean | Whether multitenancy is allowed.<br>*Example:* `false` | No |
| policyEditor | boolean | Whether the editing of policies is allowed.<br>*Example:* `true` | No |
| policyManager | boolean | Whether the policy manager is allowed.<br>*Example:* `true` | No |
| remediationAnalytics | boolean | Whether Remediation Analytics features are available.<br>*Example:* `true` | No |
| reporting | [LicenseReporting](#licensereporting) | The reporting features available in the license.<br>*Example:* `""` | No |
| scanning | [LicenseScanning](#licensescanning) | The scanning features available in the license.<br>*Example:* `""` | No |

#### File

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| attributes | [ [Configuration](#configuration) ] | Attributes detected on the file. | No |
| name | string | The name of the file.<br>*Example:* `"ADMIN$"` | Yes |
| size | long | The size of the regular file (in bytes). If the file is a directory, no value is returned.<br>*Example:* `-1` | No |
| type | string | The type of the file.<br>*Enum:* `"file"`, `"directory"`<br>*Example:* `"directory"` | Yes |

#### Fingerprint

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| description | string | The description of the matched fingerprint.<br>*Example:* `"Ubuntu libexpat1 2.1.0-4ubuntu1.2"` | No |
| family | string | The family of the matched fingerprint.<br>*Example:* `""` | No |
| product | string | The product of the matched fingerprint.<br>*Example:* `"libexpat1"` | No |
| vendor | string | The description of the matched fingerprint.<br>*Example:* `"Ubuntu"` | No |
| version | string | The version of the matched fingerprint.<br>*Example:* `"2.1.0-4ubuntu1.2"` | No |

#### GlobalScan

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | integer | The number of assets found in the scan.<br>*Example:* `""` | No |
| duration | string | The duration of the scan in ISO8601 format.<br>*Example:* `""` | No |
| endTime | string | The end time of the scan in ISO8601 format.<br>*Example:* `""` | No |
| engineId | integer | The identifier of the scan engine.<br>*Example:* `""` | No |
| engineIds | [ [EngineID](#engineid) ] | ${scan.engine.ids} | No |
| engineName | string | The name of the scan engine.<br>*Example:* `""` | No |
| id | long | The identifier of the scan.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The reason for the scan status.<br>*Example:* `""` | No |
| scanName | string | The user-driven scan name for the scan.<br>*Example:* `""` | No |
| scanType | string | The scan type (automated, manual, scheduled). <br>*Example:* `""` | No |
| siteId | integer |  | No |
| siteName | string |  | No |
| startTime | string | The start time of the scan in ISO8601 format.<br>*Example:* `""` | No |
| startedBy | string | The name of the user that started the scan.<br>*Example:* `""` | No |
| startedByUsername | string | ${scan.username}<br>*Example:* `""` | No |
| status | string | The scan status.<br>*Enum:* `"aborted"`, `"unknown"`, `"running"`, `"finished"`, `"stopped"`, `"error"`, `"paused"`, `"dispatched"`, `"integrating"`<br>*Example:* `""` | No |
| vulnerabilities | [Vulnerabilities](#vulnerabilities) | The vulnerability synopsis of the scan.<br>*Example:* `""` | No |

#### GroupAccount

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the user group.<br>*Example:* `972` | No |
| name | string | The name of the user group.<br>*Example:* `"Administrators"` | Yes |

#### HostName

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| name | string | The host name (local or FQDN).<br>*Example:* `"corporate-workstation-1102DC.acme.com"` | Yes |
| source | string | The source used to detect the host name. `user` indicates the host name source is user-supplied (e.g. in a site target definition).<br>*Enum:* `"user"`, `"dns"`, `"netbios"`, `"dce"`, `"epsec"`, `"ldap"`, `"other"`<br>*Example:* `"DNS"` | No |

#### IMetaData

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| fieldName | string |  | No |
| supportedOperators | [ string ] |  | No |
| type | string | *Enum:* `"NUMERIC"`, `"STRING"`, `"SET"`, `"SET_STRING"`, `"SINGLE"`, `"DATE"` | No |

#### IncludedAssetGroups

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assetGroupIDs | [ integer ] | List of asset group identifiers. Each element is an integer. | No |
| links | [ [Link](#link) ] |  | No |

#### IncludedScanTargets

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ string ] | List of addresses. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No |
| links | [ [Link](#link) ] |  | No |

#### Info

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| cpu | [CPUInfo](#cpuinfo) | Details regarding the host CPU.<br>*Example:* `""` | No |
| disk | [DiskInfo](#diskinfo) | Details regarding host disk usage.<br>*Example:* `""` | No |
| distinguishedName | string | The distinguished name of the console.<br>*Example:* `"CN=Rapid7 Security Console/ O=Rapid7"` | No |
| fqdn | string | The fully-qualified domain name of the local host the service is running on.<br>*Example:* `"server.acme.com"` | No |
| host | string | The name of the local host the service is running on.<br>*Example:* `"SERVER"` | No |
| ip | string | The IP address of the local host the service is running on.<br>*Example:* `"192.168.1.99"` | No |
| jvm | [JVMInfo](#jvminfo) | Details regarding the Java Virtual Machine.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| memory | [MemoryInfo](#memoryinfo) | Details regarding host memory usage.<br>*Example:* `""` | No |
| operatingSystem | string | The operating system of the host the service is running on.<br>*Example:* `"Ubuntu Linux 16.04"` | No |
| serial | string | The serial number of the console.<br>*Example:* `"729F31B1C92F3C91DFA8A649F4D5C883C269BD45"` | No |
| superuser | boolean | Whether the service is running a super-user.<br>*Example:* `true` | No |
| user | string | The user running the service.<br>*Example:* `"root"` | No |
| version | [VersionInfo](#versioninfo) | Details regarding the version of the installation.<br>*Example:* `""` | No |

#### InstallSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| backups | [BackupsSize](#backupssize) | The disk space used by backups.<br>*Example:* `""` | No |
| database | [DatabaseSize](#databasesize) | The disk space used by the database.<br>*Example:* `""` | No |
| directory | string | The installation directory.<br>*Example:* `""` | No |
| reports | [ReportSize](#reportsize) | The disk space used by reports.<br>*Example:* `""` | No |
| scans | [ScanSize](#scansize) | The disk space used by scans.<br>*Example:* `""` | No |
| total | [InstallationTotalSize](#installationtotalsize) | Total disk space used by the installation.<br>*Example:* `""` | No |

#### InstallationTotalSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `12125933077` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"11.3 GB"` | No |

#### InternalServerError

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"500"`<br>*Example:* `"500"` | Yes |

#### JVMInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| name | string | The name of the Java Virtual Machine.<br>*Example:* `"OpenJDK 64-Bit Server VM"` | No |
| startTime | string | The date and time the Java Virtual Machine last started.<br>*Example:* `"2018-02-13T20:35:35.076Z"` | No |
| uptime | string | Total up-time of the Java Virtual Machine, in ISO 8601 format. For example: `"PT1H4M24.214S"`.<br>*Example:* `"PT8H21M7.978S"` | No |
| vendor | string | The vendor of the Java Virtual Machine.<br>*Example:* `"Azul Systems, Inc."` | No |
| version | string | The version of the Java Virtual Machine.<br>*Example:* `"25.102-b14"` | No |

#### JsonNode

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| array | boolean |  | No |
| bigDecimal | boolean |  | No |
| bigInteger | boolean |  | No |
| binary | boolean |  | No |
| boolean | boolean |  | No |
| containerNode | boolean |  | No |
| double | boolean |  | No |
| float | boolean |  | No |
| floatingPointNumber | boolean |  | No |
| int | boolean |  | No |
| integralNumber | boolean |  | No |
| long | boolean |  | No |
| missingNode | boolean |  | No |
| nodeType | string | *Enum:* `"ARRAY"`, `"BINARY"`, `"BOOLEAN"`, `"MISSING"`, `"NULL"`, `"NUMBER"`, `"OBJECT"`, `"POJO"`, `"STRING"` | No |
| null | boolean |  | No |
| number | boolean |  | No |
| object | boolean |  | No |
| pojo | boolean |  | No |
| short | boolean |  | No |
| textual | boolean |  | No |
| valueNode | boolean |  | No |

#### License

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| edition | string | The edition of the product.<br>*Example:* `"InsightVM"` | No |
| evaluation | boolean | Whether the license is a time-restricted evaluation.<br>*Example:* `false` | No |
| expires | string | The date and time the license expires.<br>*Example:* `"2018-12-31T23:59:59.999Z"` | No |
| features | [Features](#features) | The features available in the license.<br>*Example:* `""` | No |
| limits | [LicenseLimits](#licenselimits) | The limits of the license.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| perpetual | boolean | Whether the license is perpetual.<br>*Example:* `false` | No |
| status | string | The status of the license.<br>*Enum:* `"Activated"`, `"Unlicensed"`, `"Expired"`, `"Evaluation Mode"`, `"Revoked"`, `"Unknown"`<br>*Example:* `"Activated"` | No |

#### LicenseLimits

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | integer | The maximum number of assets that can be assessed.<br>*Example:* `100000` | No |
| assetsWithHostedEngine | integer | The maximum number of assets that may be scanned with the hosted scan engine.<br>*Example:* `1000` | No |
| scanEngines | integer | The maximum number of scan engines that may be used.<br>*Example:* `100` | No |
| users | integer | The maximum number of users allowed.<br>*Example:* `1000` | No |

#### LicensePolicyScanning

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| benchmarks | [LicensePolicyScanningBenchmarks](#licensepolicyscanningbenchmarks) | The benchmarks available to policy scan.<br>*Example:* `""` | No |
| scanning | boolean | Whether policy scanning is allowed.<br>*Example:* `true` | No |

#### LicensePolicyScanningBenchmarks

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| cis | boolean | Whether policy scanning for CIS benchmarks is allowed.<br>*Example:* `true` | No |
| custom | boolean | Whether custom benchmarks can be used during scanning.<br>*Example:* `true` | No |
| disa | boolean | Whether policy scanning for DISA benchmarks is allowed.<br>*Example:* `true` | No |
| fdcc | boolean | Whether policy scanning for FDCC benchmarks is allowed.<br>*Example:* `true` | No |
| usgcb | boolean | Whether policy scanning for USGCB benchmarks is allowed.<br>*Example:* `true` | No |

#### LicenseReporting

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| advanced | boolean | Whether advanced reporting is available.<br>*Example:* `true` | No |
| customizableCSVExport | boolean | Whether customizable CSV Export is available.<br>*Example:* `true` | No |
| pci | boolean | Whether PCI reporting is available.<br>*Example:* `true` | No |

#### LicenseScanning

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| discovery | boolean | Whether discovery scanning may be used.<br>*Example:* `true` | No |
| policy | [LicensePolicyScanning](#licensepolicyscanning) | Details as to whether policy scanning and what benchmarks are available.<br>*Example:* `"true"` | No |
| scada | boolean | Whether SCADA scanning may be used.<br>*Example:* `true` | No |
| virtual | boolean | Whether virtual scanning may be used.<br>*Example:* `true` | No |
| webApplication | boolean | Whether web scanning may be used.<br>*Example:* `true` | No |

#### Link

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| href | string | A hypertext reference, which is either a URI (see <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>) or URI template (see <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc6570">RFC 6570</a>). <br>*Example:* `"https://hostname:3780/api/3/..."` | No |
| rel | string | The link relation type. This value is one from the <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc5988#section-6.2">Link Relation Type Registry</a> or is the type of resource being linked to.<br>*Example:* `"self"` | No |

#### Links

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### LocalePreferences

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| default | string | The default language to use. The format is a <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/bcp47">IETF BCP 47</a> language tag.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| reports | string | The language to use to generate reports. The format is a <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/bcp47">IETF BCP 47</a> language tag.<br>*Example:* `""` | No |

#### MalwareKit

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the malware kit.<br>*Example:* `152` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the malware kit.<br>*Example:* `"Alpha Pack"` | No |
| popularity | string | The name of the malware kit. One of: `"Rare"`, `"Uncommon"`, `"Occasional"`, `"Common"`, `"Popular"`, `"Favored"`, `"Unknown"`<br>*Example:* `"Rare"` | No |

#### MatchedSolution

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| additionalInformation | [AdditionalInformation](#additionalinformation) | Additional information or resources that can assist in applying the remediation.<br>*Example:* `""` | No |
| appliesTo | string | The systems or software the solution applies to.<br>*Example:* `"libexpat1 on Ubuntu Linux"` | No |
| confidence | string | The confidence of the matching process for the solution.<br>*Enum:* `"exact"`, `"partial"`, `"none"`<br>*Example:* `""` | No |
| estimate | string | The estimated duration to apply the solution, in ISO 8601 format. For example: `"PT5M"`.<br>*Example:* `"PT10M"` | No |
| id | string | The identifier of the solution.<br>*Example:* `"ubuntu-upgrade-libexpat1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| matches | [ [SolutionMatch](#solutionmatch) ] | The raw matches that were performed in order to select the best solution(s). | No |
| steps | [Steps](#steps) | The steps required to remediate the vulnerability.<br>*Example:* `""` | No |
| summary | [Summary](#summary) | The summary of the solution.<br>*Example:* `""` | No |
| type | string | The type of the solution. One of: `"Configuration"`, `"Rollup patch"`, `"Patch"`<br>*Enum:* `"configuration"`, `"rollup-patch"`, `"patch"`, `"unknown"`<br>*Example:* `"configuration"` | No |

#### MemoryFree

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `45006848` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"42.9 MB"` | No |

#### MemoryInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| free | [MemoryFree](#memoryfree) | Free memory.<br>*Example:* `""` | No |
| total | [MemoryTotal](#memorytotal) | Total memory usage.<br>*Example:* `""` | No |

#### MemoryTotal

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `17179869184` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"16 GB"` | No |

#### NotFoundError

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"404"`<br>*Example:* `"404"` | Yes |

#### OperatingSystem

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| architecture | string | The architecture of the operating system.<br>*Example:* `"x86"` | No |
| configurations | [ [Configuration](#configuration) ] | Configuration key-values pairs enumerated on the operating system. | No |
| cpe | [OperatingSystemCpe](#operatingsystemcpe) | The Common Platform Enumeration (CPE) of the operating system.<br>*Example:* `""` | No |
| description | string | The description of the operating system (containing vendor, family, product, version and architecture in a single string).<br>*Example:* `"Microsoft Windows Server 2008 Enterprise Edition SP1"` | No |
| family | string | The family of the operating system.<br>*Example:* `"Windows"` | No |
| id | long | The identifier of the operating system.<br>*Example:* `35` | No |
| product | string | The name of the operating system.<br>*Example:* `"Windows Server 2008 Enterprise Edition"` | No |
| systemName | string | A combination of vendor and family (with redundancies removed), suitable for grouping.<br>*Example:* `"Microsoft Windows"` | No |
| type | string | The type of operating system.<br>*Example:* `"Workstation"` | No |
| vendor | string | The vendor of the operating system.<br>*Example:* `"Microsoft"` | No |
| version | string | The version of the operating system.<br>*Example:* `"SP1"` | No |

#### OperatingSystemCpe

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| edition | string | Edition-related terms applied by the vendor to the product. <br>*Example:* `"enterprise"` | No |
| language | string | Defines the language supported in the user interface of the product being described. The format is of the language tag adheres to <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc5646">RFC5646</a>.<br>*Example:* `""` | No |
| other | string | Captures any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value. <br>*Example:* `""` | No |
| part | string | A single letter code that designates the particular platform part that is being identified.<br>*Enum:* `"o"`, `"a"`, `"h"`<br>*Example:* `"o"` | Yes |
| product | string | the most common and recognizable title or name of the product.<br>*Example:* `"windows_server_2008"` | No |
| swEdition | string | Characterizes how the product is tailored to a particular market or class of end users. <br>*Example:* `""` | No |
| targetHW | string | Characterize the instruction set architecture on which the product operates. <br>*Example:* `""` | No |
| targetSW | string | Characterize the software computing environment within which the product operates.<br>*Example:* `""` | No |
| update | string | Vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.<br>*Example:* `"sp1"` | No |
| v2.2 | string | The full CPE string in the <a target="_blank" rel="noopener noreferrer" href="https://cpe.mitre.org/files/cpe-specification_2.2.pdf">CPE 2.2</a> format.<br>*Example:* `"cpe:/o:microsoft:windows_server_2008:-:sp1:enterprise"` | No |
| v2.3 | string | The full CPE string in the <a target="_blank" rel="noopener noreferrer" href="http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf">CPE 2.3</a> format.<br>*Example:* `"cpe:2.3:o:microsoft:windows_server_2008:-:sp1:enterprise:*:*:*:*:*"` | No |
| vendor | string | The person or organization that manufactured or created the product.<br>*Example:* `"microsoft"` | No |
| version | string | Vendor-specific alphanumeric strings characterizing the particular release version of the product.<br>*Example:* `"-"` | No |

#### PCI

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| adjustedCVSSScore | integer | The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10.<br>*Example:* `4` | No |
| adjustedSeverityScore | integer | The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10.<br>*Example:* `3` | No |
| fail | boolean | Whether if present on a host this vulnerability would cause a PCI failure. `true` if "status" is `"Fail"`, `false` otherwise.<br>*Example:* `true` | No |
| specialNotes | string | Any special notes or remarks about the vulnerability that pertain to PCI compliance.<br>*Example:* `""` | No |
| status | string | The PCI compliance status of the vulnerability. One of: `"Pass"`, `"Fail"`.<br>*Example:* `"Fail"` | No |

#### PageInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| number | long | The index (zero-based) of the current page returned.<br>*Example:* `6` | No |
| size | long | The maximum size of the page returned.<br>*Example:* `10` | No |
| totalPages | long | The total number of pages available.<br>*Example:* `13` | No |
| totalResources | long | The total number of resources available across all pages.<br>*Example:* `123` | No |

#### PageOf«Agent»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Agent](#agent) ] | The page of resources returned. | No |

#### PageOf«AssetGroup»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [AssetGroup](#assetgroup) ] | The page of resources returned. | No |

#### PageOf«AssetPolicyItem»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [AssetPolicyItem](#assetpolicyitem) ] | The page of resources returned. | No |

#### PageOf«AssetPolicy»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [AssetPolicy](#assetpolicy) ] | The page of resources returned. | No |

#### PageOf«Asset»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Asset](#asset) ] | The page of resources returned. | No |

#### PageOf«DiscoveryConnection»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [DiscoveryConnection](#discoveryconnection) ] | The page of resources returned. | No |

#### PageOf«Exploit»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Exploit](#exploit) ] | The page of resources returned. | No |

#### PageOf«GlobalScan»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [GlobalScan](#globalscan) ] | The page of resources returned. | No |

#### PageOf«MalwareKit»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [MalwareKit](#malwarekit) ] | The page of resources returned. | No |

#### PageOf«OperatingSystem»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [OperatingSystem](#operatingsystem) ] | The page of resources returned. | No |

#### PageOf«PolicyAsset»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyAsset](#policyasset) ] | The page of resources returned. | No |

#### PageOf«PolicyControl»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyControl](#policycontrol) ] | The page of resources returned. | No |

#### PageOf«PolicyGroup»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyGroup](#policygroup) ] | The page of resources returned. | No |

#### PageOf«PolicyItem»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyItem](#policyitem) ] | The page of resources returned. | No |

#### PageOf«PolicyOverride»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyOverride](#policyoverride) ] | The page of resources returned. | No |

#### PageOf«PolicyRule»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [PolicyRule](#policyrule) ] | The page of resources returned. | No |

#### PageOf«Policy»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Policy](#policy) ] | The page of resources returned. | No |

#### PageOf«Report»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Report](#report) ] | The page of resources returned. | No |

#### PageOf«Scan»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Scan](#scan) ] | The page of resources returned. | No |

#### PageOf«Site»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Site](#site) ] | The page of resources returned. | No |

#### PageOf«Software»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Software](#software) ] | The page of resources returned. | No |

#### PageOf«Tag»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Tag](#tag) ] | The page of resources returned. | No |

#### PageOf«User»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [User](#user) ] | The page of resources returned. | No |

#### PageOf«VulnerabilityCategory»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [VulnerabilityCategory](#vulnerabilitycategory) ] | The page of resources returned. | No |

#### PageOf«VulnerabilityCheck»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [VulnerabilityCheck](#vulnerabilitycheck) ] | The page of resources returned. | No |

#### PageOf«VulnerabilityException»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [VulnerabilityException](#vulnerabilityexception) ] | The page of resources returned. | No |

#### PageOf«VulnerabilityFinding»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [VulnerabilityFinding](#vulnerabilityfinding) ] | The page of resources returned. | No |

#### PageOf«VulnerabilityReference»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [VulnerabilityReference](#vulnerabilityreference) ] | The page of resources returned. | No |

#### PageOf«Vulnerability»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| page | [PageInfo](#pageinfo) | The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.<br>*Example:* `""` | No |
| resources | [ [Vulnerability](#vulnerability) ] | The page of resources returned. | No |

#### PasswordResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| password | string |  | No |

#### Policy

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| enabled | [ long ] | The identifiers of the policies enabled to be checked during a scan. No policies are enabled by default. | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| recursiveWindowsFSSearch | boolean | Whether recursive windows file searches are enabled, if your internal security practices require this capability. Recursive file searches can increase scan times by several hours, depending on the number of files and other factors, so this setting is disabled for Windows systems by default. Defaults to `false`.<br>*Example:* `false` | No |
| storeSCAP | boolean | Whether Asset Reporting Format (ARF) results are stored. If you are required to submit reports of your policy scan results to the U.S. government in ARF for SCAP certification, you will need to store SCAP data so that it can be exported in this format. Note that stored SCAP data can accumulate rapidly, which can have a significant impact on file storage. Defaults to `false`.<br>*Example:* `false` | No |

#### PolicyAsset

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| hostname | string | The primary host name (local or FQDN) of the asset.<br>*Example:* `""` | No |
| id | long | The identifier of the asset.<br>*Example:* `""` | No |
| ip | string | The primary IPv4 or IPv6 address of the asset.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| os | [OperatingSystem](#operatingsystem) | The full description of the operating system of the asset.<br>*Example:* `""` | No |
| status | string | The overall compliance status of the asset. <br>*Enum:* `"passed"`, `"failed"`, `"notApplicable"`<br>*Example:* `""` | No |

#### PolicyBenchmark

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the policy's benchmark.<br>*Example:* `""` | No |
| title | string | The title of the policy benchmark.<br>*Example:* `""` | No |
| version | string | The version number of the benchmark that includes the policy.<br>*Example:* `""` | No |

#### PolicyControl

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| cceItemId | string | The identifier of the CCE item.<br>*Example:* `""` | No |
| ccePlatform | string | The platform of the CCE.<br>*Example:* `""` | No |
| controlName | string | The name of the control mapping.<br>*Example:* `""` | No |
| id | string | The textual representation of the control identifier.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| publishedDate | long | The published date of the control mapping.<br>*Example:* `""` | No |

#### PolicyGroup

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [AssetPolicyAssessment](#assetpolicyassessment) | A summary of asset compliance.<br>*Example:* `""` | No |
| benchmark | [PolicyBenchmark](#policybenchmark) | Information about the policy benchmark.<br>*Example:* `""` | No |
| description | string | A description of the policy group.<br>*Example:* `""` | No |
| id | string | The textual representation of the policy group identifier.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the policy group.<br>*Example:* `""` | No |
| policy | [PolicyMetadataResource](#policymetadataresource) | Information about the policy.<br>*Example:* `""` | No |
| scope | string | The textual representation of the policy group scope. Policy groups that are automatically available have `"Built-in"` scope, whereas policy groups created by users have scope as `"Custom"`.<br>*Example:* `""` | No |
| status | string | The overall compliance status of the policy group.<br>*Enum:* `"PASS"`, `"FAIL"`, `"NOT_APPLICABLE"`<br>*Example:* `""` | No |
| surrogateId | long | The identifier of the policy group.<br>*Example:* `""` | No |
| title | string | The title of the policy group as visible to the user.<br>*Example:* `""` | No |

#### PolicyItem

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [AssetPolicyAssessment](#assetpolicyassessment) | A summary of asset compliance.<br>*Example:* `""` | No |
| description | string | A description of the policy rule or group.<br>*Example:* `""` | No |
| hasOverride | boolean | A flag indicating whether the policy rule has an active override applied to it. This field only applies to resources representing policy rules. <br>*Example:* `false` | No |
| id | long | The identifier of the policy rule or group.<br>*Example:* `""` | No |
| isUnscored | boolean | A flag indicating whether the policy rule has a role of `"unscored"`. This field only applies to resources representing policy rules.<br>*Example:* `false` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the policy rule or group.<br>*Example:* `""` | No |
| policy | [PolicyMetadataResource](#policymetadataresource) | Information about the policy.<br>*Example:* `""` | No |
| rules | [PolicyRuleAssessmentResource](#policyruleassessmentresource) | A summary of rule compliance for multiple policy rules. This field only applies to resources representing policy groups.<br>*Example:* `""` | No |
| scope | string | The textual representation of the policy rule/group scope. Policy rules or groups that are automatically available have `"Built-in"` scope, whereas policy rules or groups created by users have scope as `"Custom"`.<br>*Example:* `""` | No |
| status | string | The overall compliance status of the policy rule or group.<br>*Enum:* `"PASS"`, `"FAIL"`, `"NOT_APPLICABLE"`<br>*Example:* `""` | No |
| title | string | The title of the policy rule, or group, as visible to the user.<br>*Example:* `""` | No |
| type | string | Indicates whether the resource represents either a policy rule or group.<br>*Enum:* `"rule"`, `"group"`<br>*Example:* `""` | No |

#### PolicyMetadataResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the policy.<br>*Example:* `""` | No |
| title | string | The title of the policy as visible to the user.<br>*Example:* `""` | No |
| version | string | The version of the policy.<br>*Example:* `""` | No |

#### PolicyOverride

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| expires | string | The date the policy override is set to expire. Date is represented in ISO 8601 format.<br>*Example:* `""` | No |
| id | long | The identifier of the policy override.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| review | [PolicyOverrideReviewer](#policyoverridereviewer) | Details regarding the review and/or approval of the policy override.<br>*Example:* `""` | No |
| scope | [PolicyOverrideScope](#policyoverridescope) | The scope of the policy override. Indicates which assets' policy compliance results are to be affected by the override.<br>*Example:* `""` | Yes |
| state | string | The state of the policy override. Can be one of the following values:  \| Value            \| Description                                                                         \| Affects Compliance Results \|  \| ---------------- \| ----------------------------------------------------------------------------------- \|:--------------------------:\|  \| `"deleted"`      \| The policy override has been deleted.                                               \|                            \|  \| `"expired"`      \| The policy override had an expiration date and it has expired.                      \|                            \|  \| `"approved"`     \| The policy override was submitted and approved.                                     \| &check;                    \|  \| `"rejected"`     \| The policy override was rejected by the reviewer.                                   \|                            \|  \| `"under-review"` \| The policy override was submitted but not yet approved or rejected by the reviewer. \|                            \|  <br>*Example:* `""` | Yes |
| submit | [PolicyOverrideSubmitter](#policyoverridesubmitter) | Details regarding the submission of the policy override.<br>*Example:* `""` | Yes |

#### PolicyOverrideReviewer

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| comment | string | A comment from the reviewer detailing the review. Cannot exceed 1024 characters.<br>*Example:* `""` | No |
| date | string | The date the review took place.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The identifier of the user that reviewed the policy override.<br>*Example:* `""` | No |
| user | integer | The login name of the user that reviewed the policy override.<br>*Example:* `""` | No |

#### PolicyOverrideScope

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| asset | long | The identifier of the asset whose compliance results are to be overridden. Property is required if the property `scope` is set to either `"specific-asset"` or `"specific-asset-until-next-scan"`.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| newResult | string | The new policy rule result after the override is applied.<br>*Enum:* `"pass"`, `"fail"`, `"not-applicable"`, `"fixed"`<br>*Example:* `""` | Yes |
| originalResult | string | The original policy rule result before the override was applied. This property only applies to overrides with a scope of either `"specific-asset"` or `"specific-asset-until-next-scan"`.<br>*Enum:* `"pass"`, `"fail"`, `"error"`, `"unknown"`, `"not-applicable"`, `"not-checked"`, `"not-selected"`, `"informational"`, `"fixed"`<br>*Example:* `""` | No |
| rule | long | The identifier of the policy rule whose compliance results are to be overridden.<br>*Example:* `""` | Yes |
| type | string | The scope of assets affected by the policy override. Can be one of the following values:  \| Value                              \| Description                                                                                                                                                 \|  \| ---------------------------------- \| ----------------------------------------------------------------------------------------------------------------------------------------------------------- \|  \| `"all-assets"`                     \| Overrides the compliance result of all assets evaluated with the specified policy rule.                                                                     \|  \| `"specific-asset"`                 \| Overrides the compliance result of a single asset evaluated with the specified policy rule.                                                                 \|  \| `"specific-asset-until-next-scan"` \| Overrides the compliance result of a single asset evaluated with the specified policy rule until the next time asset is evaluated against that policy rule. \|  <br>*Example:* `""` | Yes |

#### PolicyOverrideSubmitter

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| comment | string | A comment from the submitter as to why the policy override was submitted. Cannot exceed 1024 characters.<br>*Example:* `""` | Yes |
| date | string | The date the policy override was submitted.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The login name of the user that submitted the policy override.<br>*Example:* `""` | No |
| user | integer | The identifier of the user that submitted the policy override.<br>*Example:* `""` | No |

#### PolicyRule

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [AssetPolicyAssessment](#assetpolicyassessment) | A summary of asset compliance.<br>*Example:* `""` | No |
| benchmark | [PolicyBenchmark](#policybenchmark) | Information about the policy benchmark.<br>*Example:* `""` | No |
| description | string | A description of the rule.<br>*Example:* `""` | No |
| id | string | The textual representation of the policy rule identifier.<br>*Example:* `""` | No |
| isCustom | boolean | A flag indicating whether the policy rule is custom.<br>*Example:* `false` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the rule.<br>*Example:* `""` | No |
| role | string | The role of the policy rule. It's value determines how it's results affect compliance.<br>*Enum:* `"full"`, `"unscored"`, `"unchecked"`<br>*Example:* `""` | No |
| scope | string | The textual representation of the policy rule scope. Policy rules that are automatically available have `"Built-in"` scope, whereas policy rules created by users have scope as `"Custom"`.<br>*Example:* `""` | No |
| status | string | The overall compliance status of the policy rule.<br>*Enum:* `"PASS"`, `"FAIL"`, `"NOT_APPLICABLE"`<br>*Example:* `""` | No |
| surrogateId | long | The identifier of the policy rule.<br>*Example:* `""` | No |
| title | string | The title of the policy rule as visible to the user.<br>*Example:* `""` | No |

#### PolicyRuleAssessmentResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| total | integer | The total number of policy rules.<br>*Example:* `""` | No |
| totalFailed | integer | The total number of policy rules that are not compliant against all assets.<br>*Example:* `""` | No |
| totalNotApplicable | integer | The total number of policy rules that are not applicable against all assets.<br>*Example:* `""` | No |
| totalPassed | integer | The total number of policy rules that are compliant against all assets.<br>*Example:* `""` | No |
| unscored | integer | The total number of policy rules that have a role of `"unscored"`.<br>*Example:* `""` | No |

#### PolicySummaryResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| decreasedCompliance | integer | The total number of policies whose overall compliance has decreased between the last two scans of all assets. The list of scanned policies is based on the user's list of accessible assets.<br>*Example:* `""` | No |
| increasedCompliance | integer | The total number of policies whose overall compliance has increased between the last two scans of all assets. The list of scanned policies is based on the user's list of accessible assets.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| numberOfPolicies | integer | The total number of policies available in the Security Console.<br>*Example:* `""` | No |
| overallCompliance | float | The ratio of compliant rules to the total number of rules across all policies.<br>*Example:* `""` | No |
| scannedPolicies | integer | The total number of policies that were evaluated against assets and have applicable results. The assets considered in the calculation are based on the user's list of accessible assets.<br>*Example:* `""` | No |

#### Privileges

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] |  | No |
| resources | [ string ] |  | No |

#### RangeResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| every | string | If `from` is a custom date the interval amount between reporting periods.<br>*Enum:* `"day"`, `"month"`, `"year"`<br>*Example:* `"day"` | No |
| from | string | The start date of the trend, which can either be a duration or a specific date and time.<br>*Enum:* `"P1Y"`, `"P6M"`, `"P3M"`, `"P1M"`, `"<date>"`<br>*Example:* `""` | No |
| interval | integer | If `from` is a custom date the interval between reporting periods. <br>*Example:* `7` | No |
| to | string | The end date of the trend (empty if `from` is a duration).<br>*Example:* `""` | No |

#### ReferenceWithEndpointIDLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| port | integer | The port of the service.<br>*Example:* `22` | No |
| protocol | string | The protocol of the service.<br>*Enum:* `"ip"`, `"icmp"`, `"igmp"`, `"ggp"`, `"tcp"`, `"pup"`, `"udp"`, `"idp"`, `"esp"`, `"nd"`, `"raw"`<br>*Example:* `"tcp"` | No |

#### ReferenceWithReportIDLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the report instance.<br>*Example:* `1` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«AlertID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«AssetID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«EngineID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«ScanScheduleID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«SiteID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«TagID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferenceWith«UserID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the resource.<br>*Example:* `"<id>"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ReferencesWith«AssetGroupID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ integer ] | The identifiers of the associated resources. | No |

#### ReferencesWith«AssetID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ long ] | The identifiers of the associated resources. | No |

#### ReferencesWith«EngineID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ integer ] | The identifiers of the associated resources. | No |

#### ReferencesWith«ReferenceWithEndpointIDLink,ServiceLink»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [ServiceLink](#servicelink) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ReferenceWithEndpointIDLink](#referencewithendpointidlink) ] | The identifiers of the associated resources. | No |

#### ReferencesWith«SiteID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ integer ] | The identifiers of the associated resources. | No |

#### ReferencesWith«SolutionNaturalID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ string ] | The identifiers of the associated resources. | No |

#### ReferencesWith«TagID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ integer ] | The identifiers of the associated resources. | No |

#### ReferencesWith«UserID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ integer ] | The identifiers of the associated resources. | No |

#### ReferencesWith«VulnerabilityCheckID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ string ] | The identifiers of the associated resources. | No |

#### ReferencesWith«VulnerabilityCheckTypeID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ string ] | The identifiers of the associated resources. | No |

#### ReferencesWith«VulnerabilityNaturalID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ string ] | The identifiers of the associated resources. | No |

#### ReferencesWith«WebApplicationID,Link»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ long ] | The identifiers of the associated resources. | No |

#### RemediationResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| solutions | integer | The number of remediations to display.<br>*Example:* `25` | No |
| sort | string | The attribute to prioritize remediation impact. Only supported for the `prioritized-remediations` and `prioritized-remediations-with-details` templates.<br>*Enum:* `"assets"`, `"vulnerabilities"`, `"malware_kits"`, `"exploits"`, `"riskscore"`<br>*Example:* `""` | No |

#### Repeat

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| dayOfWeek | string | The day of the week the scheduled task should repeat. This property only applies to schedules with a `every` value of `"day-of-month"`.<br>*Example:* `""` | No |
| every | string | The frequency schedule repeats. Each value represents a different unit of time and is used in conjunction with the property `interval`. For example, a schedule can repeat hourly, daily, monthly, etc. The following table describes each supported value:  \| Value \| Description \|  \| ---------- \| ---------------- \|  \| hour \| Specifies the schedule repeats in hourly increments. \|  \| day \| Specifies the schedule repeats in daily increments. \|  \| week \| Specifies the schedule repeats in weekly increments. \|  \| date-of-month \| Specifies the schedule repeats nth day of the `interval` month. Requires the property `dateOfMonth` to be specified. For example, if `dateOfMonth` is `17` and the `interval` is `2`, then the schedule will repeat every 2 months on the 17th day of the month. \|  \| day-of-month \| Specifies the schedule repeats on a monthly interval but instead of a specific date being specified, the day of the week and week of the month are specified. Requires the properties `dayOfWeek` and `weekOfMonth` to be specified. For example, if `dayOfWeek` is `"friday"`, `weekOfMonth` is `3`, and the `interval` is `4`, then the schedule will repeat every 4 months on the 3rd Friday of the month. \|  <br>*Example:* `"date-of-month"` | Yes |
| interval | integer | The interval time the schedule should repeat. The is depends on the value set in `every`. For example, if the value in property `every` is set to `"day"` and `interval` is set to `2`, then the schedule will repeat every 2 days.<br>*Example:* `1` | Yes |
| lastDayOfMonth | boolean | Whether to run the scheduled task on the last day of the month.<br>*Example:* `false` | No |
| weekOfMonth | integer | The week of the month the scheduled task should repeat. For This property only applies to schedules with a `every` value of `"day-of-month"`. Each week of the month is counted in 7-day increments. For example, week 1 consists of days 1-7 of the month while week 2 consists of days 8-14 of the month and so forth.<br>*Example:* `""` | No |

#### Report

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| baseline | object | If the template is `baseline-comparison` or `executive-overview` the baseline scan to compare against. This can be the `first` scan, the `previous` scan, or a scan as of a specified date. Defaults to `previous`.<br>*Example:* `""` | No |
| bureau | string | The name of the bureau for a CyberScope report. Only used when the format is `"cyberscope-xml"`.<br>*Example:* `"Bureau"` | No |
| component | string | The name of the component for a CyberScope report. Only used when the format is `"cyberscope-xml"`.<br>*Example:* `"Component"` | No |
| email | [ReportEmail](#reportemail) | Email distribution settings for the report.<br>*Example:* `""` | No |
| enclave | string | The name of the enclave for a CyberScope report. Only used when the format is `"cyberscope-xml"`.<br>*Example:* `"Enclave"` | No |
| filters | [ReportConfigFiltersResource](#reportconfigfiltersresource) | Filters applied to the contents of the report. The supported filters for a report vary  by format and template.  <div class="properties">  <div class="property-info">  <span class="property-name">categories</span> <span class="param-type complex">Object</span>  <div class="redoc-markdown-block">The vulnerability categories to include or exclude in the report. Only included or excluded may be specified, not both.</div> </div>  <div class="properties nested">  <div class="property-info">  <span class="property-name">included</span> <span class="param-type param-array-format integer">Array[string]</span>  <div class="redoc-markdown-block">The identifiers of the vulnerability categories to included in the report.</div>  </div>  <div class="property-info">  <span class="property-name">excluded</span> <span class="param-type param-array-format integer">Array[string]</span>  <div class="redoc-markdown-block">The identifiers of the vulnerability categories to exclude in the report.</div>  </div>  </div>  <div class="property-info">  <span class="property-name">severity</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"all"</span>  <span class="param-enum-value string">"critical"</span>  <span class="param-enum-value string">"critical-and-severe"</span>  </div>  <div class="redoc-markdown-block">The vulnerability severities to include in the report.</div> </div>  <div class="property-info">  <span class="property-name">statuses</span> <span class="param-type param-array-format integer">Array[string]</span>  <div class="param-enum">  <span class="param-enum-value string">"vulnerable"</span>  <span class="param-enum-value string">"vulnerable-version"</span>  <span class="param-enum-value string">"potentially-vulnerable"</span>  <span class="param-enum-value string">"vulnerable-and-validated"</span>  </div>  <div class="redoc-markdown-block">The vulnerability statuses to include in the report. If <code>"vulnerable-and-validated"</code> is selected  no other values can be specified. </div>  </div>  </div>  The following filter elements may be defined for non-templatized report formats:  \| Format                                \| Categories     \| Severity   \| Statuses   \|  \| ------------------------------------- \|:--------------:\|:----------:\|:----------:\|  \| `arf-xml`                             \|                \|            \|            \|  \| `csv-export`                          \| &check;        \| &check;    \| &check;    \|  \| `cyberscope-xml`                      \|                \|            \|            \|  \| `nexpose-simple-xml`                  \| &check;        \| &check;    \|            \|  \| `oval-xml`                            \|                \|            \|            \|  \| `qualys-xml`                          \| &check;        \| &check;    \|            \|  \| `scap-xml`                            \| &check;        \| &check;    \|            \|  \| `sql-query`                           \| &check;        \| &check;    \| &check;    \|  \| `xccdf-csv`                           \|                \|            \|            \|  \| `xccdf-xml`                           \| &check;        \| &check;    \|            \|  \| `xml-export`                          \| &check;        \| &check;    \| &check;    \|  \| `xml-export-v2`                       \| &check;        \| &check;    \| &check;    \|   The following filter elements may be defined for templatized report formats:  \| Template                                \| Categories     \| Severity   \| Statuses   \|  \| --------------------------------------- \|:--------------:\|:----------:\|:----------:\|  \| `audit-report`                          \| &check;        \| &check;    \|            \|  \| `baseline-comparison`                   \|                \|            \|            \|  \| `basic-vulnerability-check-results`     \| &check;        \| &check;    \| &check;    \|  \| `executive-overview`                    \|                \|            \|            \|  \| `highest-risk-vulns`                    \|                \|            \|            \|  \| `pci-attestation-v12`                   \|                \|            \|            \|  \| `pci-executive-summary-v12`             \|                \|            \|            \|  \| `pci-vuln-details-v12`                  \|                \|            \|            \|  \| `policy-details`                        \| &check;        \| &check;    \| &check;    \|  \| `policy-eval`                           \|                \|            \|            \|  \| `policy-summary`                        \| &check;        \| &check;    \| &check;    \|  \| `prioritized-remediations`              \| &check;        \| &check;    \| &check;    \|  \| `prioritized-remediations-with-details` \| &check;        \| &check;    \| &check;    \|  \| `r7-discovered-assets`                  \| &check;        \| &check;    \| &check;    \|  \| `r7-vulnerability-exceptions`           \| &check;        \| &check;    \| &check;    \|  \| `remediation-plan`                      \| &check;        \| &check;    \|            \|  \| `report-card`                           \| &check;        \| &check;    \|            \|  \| `risk-scorecard`                        \| &check;        \| &check;    \| &check;    \|  \| `rule-breakdown-summary`                \| &check;        \| &check;    \| &check;    \|  \| `top-policy-remediations`               \| &check;        \| &check;    \| &check;    \|  \| `top-policy-remediations-with-details`  \| &check;        \| &check;    \| &check;    \|  \| `top-riskiest-assets`                   \| &check;        \| &check;    \| &check;    \|  \| `top-vulnerable-assets`                 \| &check;        \| &check;    \| &check;    \|  \| `vulnerability-trends`                  \| &check;        \| &check;    \| &check;    \|  <br>*Example:* `""` | No |
| format | string | The output format of the report. The format will restrict the available templates and parameters that can be specified.<br>*Example:* `"pdf"` | No |
| frequency | [ReportFrequency](#reportfrequency) | The recurring frequency with which to generate the report.<br>*Example:* `""` | No |
| id | integer | The identifier of the report.<br>*Example:* `17` | No |
| language | string | The locale (language) in which the report is generated<br>*Example:* `"en-US"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the report.<br>*Example:* `"Monthly Corporate Site Summary"` | No |
| organization | string | The organization used for a XCCDF XML report. Only used when the format is `"xccdf-xml"`.<br>*Example:* `"Acme, Inc."` | No |
| owner | integer | The identifier of the report owner.<br>*Example:* `1` | No |
| policies | [ long ] | If the template is `rule-breakdown-summary`, `top-policy-remediations`, or `top-policy-remediations-with-details` the identifiers of the policies to report against. | No |
| policy | long | The policy to report on. Only used when the format is `"oval-xml"`, `""xccdf-csv"`, or `"xccdf-xml"`.<br>*Example:* `789` | No |
| query | string | SQL query to run against the Reporting Data Model. Only used when the format is `"sql-query"`.<br>*Example:* `"SELECT * FROM dim_asset ORDER BY ip_address ASC"` | No |
| range | [RangeResource](#rangeresource) | If the template is `vulnerability-trends`, `r7-vulnerability-exceptions`, or `r7-discovered-assets` the date range to trend over.<br>*Example:* `""` | No |
| remediation | [RemediationResource](#remediationresource) | If the template is `prioritized-remediations`, `prioritized-remediations-with-details`, `top-policy-remediations`, or `top-policy-remediations-with-details` the remediation display settings.<br>*Example:* `""` | No |
| riskTrend | [RiskTrendResource](#risktrendresource) | Configuration details for risk trending output.<br>*Example:* `""` | No |
| scope | [ReportConfigScopeResource](#reportconfigscoperesource) | The scope of the report. Scope is an object that has the following properties that vary by format and template:  <div class="properties">  <div class="property-info">  <span class="property-name">assets</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span>  <div class="redoc-markdown-block">The identifiers of the assets to report on.</div>  </div>  <div class="property-info">  <span class="property-name">sites</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span>  <div class="redoc-markdown-block">The identifiers of the sites to report on.</div>  </div>  <div class="property-info">  <span class="property-name">assetGroups</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span>  <div class="redoc-markdown-block">The identifiers of the asset to report on.</div>  </div>  <div class="property-info">  <span class="property-name">tags</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span>  <div class="redoc-markdown-block">The identifiers of the tag to report on.</div>  </div>  <div class="property-info">  <span class="property-name">scan</span> <span class="param-type param-array-format integer">integer &lt;int32&gt;</span>  <div class="redoc-markdown-block">The identifier of the scan to report on.</div>  </div>  </div>  The following scope elements may be defined for non-templatized report formats:  \| Format                                \| Assets     \| Sites   \| Asset Groups \| Tags    \| Scan      \|  \| ------------------------------------- \|:----------:\|:-------:\|:------------:\|:-------:\|:---------:\|  \| `arf-xml`                             \| &check;    \| &check; \| &check;      \| &check; \|           \|  \| `csv-export`                          \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `cyberscope-xml`                      \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `nexpose-simple-xml`                  \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `oval-xml`                            \| &check;    \| &check; \| &check;      \| &check; \|           \|  \| `qualys-xml`                          \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `scap-xml`                            \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `sql-query`                           \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `xccdf-csv`                           \| &check;    \|         \|              \|         \|           \|  \| `xccdf-xml`                           \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `xml-export`                          \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|  \| `xml-export-v2`                       \| &check;    \| &check; \| &check;      \| &check; \| &check;   \|   The following scope elements may be defined for templatized report formats:  \| Template                                 \| Assets     \| Sites   \| Asset Groups \| Tags    \| Scan    \|  \| -----------------------------------------\|:----------:\|:-------:\|:------------:\|:-------:\|:-------:\|  \| `audit-report`                           \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `baseline-comparison`                    \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `basic-vulnerability-check-results`      \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `executive-overview`                     \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `highest-risk-vulns`                     \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `pci-attestation-v12`                    \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `pci-executive-summary-v12`              \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `pci-vuln-details-v12`                   \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `policy-details`                         \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `policy-eval`                            \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `policy-summary`                         \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `prioritized-remediations`               \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `prioritized-remediations-with-details`  \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `r7-discovered-assets`                   \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `r7-vulnerability-exceptions`            \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `remediation-plan`                       \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `report-card`                            \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `risk-scorecard`                         \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `rule-breakdown-summary`                 \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `top-policy-remediations`                \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `top-policy-remediations-with-details`   \| &check;    \| &check; \|  &check;     \| &check; \|         \|  \| `top-riskiest-assets`                    \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `top-vulnerable-assets`                  \| &check;    \| &check; \|  &check;     \| &check; \| &check; \|  \| `vulnerability-trends`                   \| &check;    \| &check; \|  &check;     \| &check; \|         \|  If a report supports specifying a scan as the scope and a scan is specified, no other scope elements may be defined.  In all other cases as many different types of supported scope elements can be specified in any combination. All  reports except the `sql-query` format require at least one element to be specified as the scope. <br>*Example:* `""` | No |
| storage | [ReportStorage](#reportstorage) | The additional storage location and path.<br>*Example:* `""` | No |
| template | string | The template for the report (only required if the format is templatized).<br>*Example:* `"executive-overview"` | No |
| timezone | string | The timezone the report generates in, such as `"America/Los_Angeles"`.<br>*Example:* `"America/Los_Angeles"` | No |
| users | [ integer ] | The identifiers of the users granted explicit access to the report.<br>*Example:* `"7"` | No |
| version | string | The version of the report Data Model to report against. Only used when the format is `"sql-query"`.<br>*Example:* `"2.3.0"` | No |

#### ReportConfigCategoryFilters

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| excluded | [ string ] | The vulnerability categories to exclude. Defaults to no categories. | No |
| included | [ string ] | The vulnerability categories to include. Defaults to all categories. | No |
| links | [ [Link](#link) ] |  | No |

#### ReportConfigFiltersResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| categories | [ReportConfigCategoryFilters](#reportconfigcategoryfilters) | Vulnerability categories to include or exclude. Only `included` or `excluded` may be specified, but not both.<br>*Example:* `""` | No |
| severity | string | The vulnerability severities to include. Defaults to `all`.<br>*Enum:* `"all"`, `"critical"`, `"critical-and-severe"`<br>*Example:* `""` | No |
| statuses | [ string ] | The vulnerability statuses to include. Defaults to [ `vulnerable`, `vulnerable-version`, `potentially-vulnerable` ]. | No |

#### ReportConfigScopeResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assetGroups | [ integer ] | Identifiers of the asset groups in the scope of the report. | No |
| assets | [ long ] | Identifiers of the assets in the scope of the report. | No |
| scan | long | Identifiers of the scans in the scope of the report.<br>*Example:* `68` | No |
| sites | [ integer ] | Identifiers of the sites in the scope of the report. | No |
| tags | [ integer ] | Identifiers of the tags in the scope of the report. | No |

#### ReportEmail

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| access | string | The format to distribute the report in when sending to users who have explicit access to the report.<br>*Enum:* `"file"`, `"zip"`, `"url"`, `"none"`<br>*Example:* `"zip"` | No |
| additional | string | The format to distribute the report to additional recipients.<br>*Enum:* `"file"`, `"zip"`, `"none"`<br>*Example:* `"file"` | No |
| additionalRecipients | [ string ] | The email address of additional recipients to distribute the report to. | No |
| assetAccess | boolean | Whether to distribute the report to all users to have access to assets in the report.<br>*Example:* `true` | No |
| owner | string | The format to distribute the report to the owner.<br>*Enum:* `"file"`, `"url"`, `"zip"`, `"none"`<br>*Example:* `"file"` | No |
| smtp | [ReportEmailSmtp](#reportemailsmtp) | SMTP delivery settings.<br>*Example:* `""` | No |

#### ReportEmailSmtp

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| global | boolean | Whether to use global SMTP settings. If enabled, `sender` and `relay` may not be specified.<br>*Example:* `true` | No |
| relay | string | SMTP relay host or IP address.<br>*Example:* `"mail.acme.com"` | No |
| sender | string | SMTP sender address.<br>*Example:* `"john_smith@acme.com"` | No |

#### ReportFilters

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| ReportFilters | object |  |  |

#### ReportFrequency

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| nextRuntimes | [ string ] | The next scheduled run-times for generation of the report when type is `schedule`. | No |
| repeat | [ReportRepeat](#reportrepeat) | How often the report generates when type is `schedule`.<br>*Example:* `""` | No |
| start | string | When the report starts generating when type is `schedule`.<br>*Example:* `"2018-03-01T04:31:56Z"` | No |
| type | string | The frequency to generate the report. `schedule` generates the report every scheduled time interval, and requires the `repeat` and `start` properties to be specified. `scan` generates the report after any scan of any element in the scope of the report. `none` does not generate the report automatically. Defaults to `none`.<br>*Enum:* `"schedule"`, `"scan"`, `"none"`<br>*Example:* `"schedule"` | No |

#### ReportInstance

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| generated | string | The date the report finished generation.<br>*Example:* `"2018-06-01T18:56:03Z"` | No |
| id | integer | The identifier of the report instance.<br>*Example:* `5` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| size | [ReportSize](#reportsize) | The size of the report, uncompressed.<br>*Example:* `""` | No |
| status | string | The status of the report generation process.<br>*Enum:* `"aborted"`, `"failed"`, `"complete"`, `"running"`, `"unknown"`<br>*Example:* `"complete"` | No |
| uri | string | The URI of the report accessible through the web console. Refer to the `Download` relation hyperlink for a download URI.<br>*Example:* `"https://hostname:3780/reports/..."` | No |

#### ReportRepeat

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| dayOfWeek | string | The day of the week the scheduled task should repeat. This property only applies to schedules with a `every` value of `"day-of-month"`.<br>*Example:* `""` | No |
| every | string | The frequency schedule repeats. Each value represents a different unit of time and is used in conjunction with the property `interval`. For example, a schedule can repeat hourly, daily, monthly, etc. The following table describes each supported value:  \| Value \| Description \|  \| ---------- \| ---------------- \|  \| hour \| Specifies the schedule repeats in hourly increments. \|  \| day \| Specifies the schedule repeats in daily increments. \|  \| week \| Specifies the schedule repeats in weekly increments. \|  \| date-of-month \| Specifies the schedule repeats nth day of the `interval` month. Requires the property `dateOfMonth` to be specified. For example, if `dateOfMonth` is `17` and the `interval` is `2`, then the schedule will repeat every 2 months on the 17th day of the month. \|  \| day-of-month \| Specifies the schedule repeats on a monthly interval but instead of a specific date being specified, the day of the week and week of the month are specified. Requires the properties `dayOfWeek` and `weekOfMonth` to be specified. For example, if `dayOfWeek` is `"friday"`, `weekOfMonth` is `3`, and the `interval` is `4`, then the schedule will repeat every 4 months on the 3rd Friday of the month. \|  <br>*Example:* `"date-of-month"` | Yes |
| interval | integer | The interval time the schedule should repeat. The is depends on the value set in `every`. For example, if the value in property `every` is set to `"day"` and `interval` is set to `2`, then the schedule will repeat every 2 days.<br>*Example:* `1` | Yes |
| weekOfMonth | integer | The week of the month the scheduled task should repeat. For This property only applies to schedules with a `every` value of `"day-of-month"`. Each week of the month is counted in 7-day increments. For example, week 1 consists of days 1-7 of the month while week 2 consists of days 8-14 of the month and so forth.<br>*Example:* `""` | No |

#### ReportScope

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| ReportScope | object |  |  |

#### ReportSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `24789050` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"23.6 MB"` | No |

#### ReportStorage

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| location | string | The location to storage an additional copy of the report. This is a sub-path post-fixed to `$(install_dir)/nsc/reports/$(user)/`. Variables such as `$(report_name)`, `$(date)`, and `$(time)` may be used to generate the directory structure. <br>*Example:* `"monthly_reports/site/corporate"` | No |
| path | string | The full path to the additional copy storage location.<br>*Example:* `"$(install_dir)/nsc/reports/$(user)/monthly_reports/site/corporate"` | No |

#### ReportTemplate

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| builtin | boolean | Whether the report template is builtin.<br>*Example:* `true` | No |
| description | string | The description of the report template.<br>*Example:* `"Provides comprehensive details about discovered assets, vulnerabilities, and users."` | No |
| id | string | The identifier of the report template;<br>*Example:* `"audit-report"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the report template.<br>*Example:* `"Audit Report"` | No |
| sections | [ string ] | The sections that comprise the `document` report template. | No |
| type | string | The type of the report template. `document` is a templatized, typically printable, report that has various sections of content. `export` is data-oriented output, typically CSV. `file` is a printable report template using a report template file.<br>*Enum:* `"document"`, `"export"`, `"file"`<br>*Example:* `"document"` | No |

#### Resources«Alert»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Alert](#alert) ] | The resources returned. | No |

#### Resources«AssetGroup»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [AssetGroup](#assetgroup) ] | The resources returned. | No |

#### Resources«AssetTag»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [AssetTag](#assettag) ] | The resources returned. | No |

#### Resources«AuthenticationSource»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [AuthenticationSource](#authenticationsource) ] | The resources returned. | No |

#### Resources«AvailableReportFormat»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [AvailableReportFormat](#availablereportformat) ] | The resources returned. | No |

#### Resources«Configuration»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Configuration](#configuration) ] | The resources returned. | No |

#### Resources«Database»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Database](#database) ] | The resources returned. | No |

#### Resources«DiscoveryAsset»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] |  | No |
| resources | [ [DiscoveryAsset](#discoveryasset) ] |  | No |

#### Resources«EnginePool»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [EnginePool](#enginepool) ] | The resources returned. | No |

#### Resources«File»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [File](#file) ] | The resources returned. | No |

#### Resources«GroupAccount»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [GroupAccount](#groupaccount) ] | The resources returned. | No |

#### Resources«MatchedSolution»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [MatchedSolution](#matchedsolution) ] | The resources returned. | No |

#### Resources«PolicyOverride»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [PolicyOverride](#policyoverride) ] | The resources returned. | No |

#### Resources«ReportInstance»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ReportInstance](#reportinstance) ] | The resources returned. | No |

#### Resources«ReportTemplate»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ReportTemplate](#reporttemplate) ] | The resources returned. | No |

#### Resources«Role»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Role](#role) ] | The resources returned. | No |

#### Resources«ScanEngine»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ScanEngine](#scanengine) ] | The resources returned. | No |

#### Resources«ScanSchedule»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ScanSchedule](#scanschedule) ] | The resources returned. | No |

#### Resources«ScanTemplate»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [ScanTemplate](#scantemplate) ] | The resources returned. | No |

#### Resources«SharedCredential»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SharedCredential](#sharedcredential) ] | The resources returned. | No |

#### Resources«SiteCredential»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SiteCredential](#sitecredential) ] | The resources returned. | No |

#### Resources«SiteSharedCredential»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SiteSharedCredential](#sitesharedcredential) ] | The resources returned. | No |

#### Resources«SmtpAlert»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SmtpAlert](#smtpalert) ] | The resources returned. | No |

#### Resources«SnmpAlert»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SnmpAlert](#snmpalert) ] | The resources returned. | No |

#### Resources«Software»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Software](#software) ] | The resources returned. | No |

#### Resources«Solution»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Solution](#solution) ] | The resources returned. | No |

#### Resources«SonarQuery»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SonarQuery](#sonarquery) ] | The resources returned. | No |

#### Resources«SyslogAlert»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [SyslogAlert](#syslogalert) ] | The resources returned. | No |

#### Resources«Tag»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [Tag](#tag) ] | The resources returned. | No |

#### Resources«UserAccount»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [UserAccount](#useraccount) ] | The resources returned. | No |

#### Resources«User»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [User](#user) ] | The resources returned. | No |

#### Resources«VulnerabilityValidationResource»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [VulnerabilityValidationResource](#vulnerabilityvalidationresource) ] | The resources returned. | No |

#### Resources«WebFormAuthentication»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [WebFormAuthentication](#webformauthentication) ] | The resources returned. | No |

#### Resources«WebHeaderAuthentication»

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [WebHeaderAuthentication](#webheaderauthentication) ] | The resources returned. | No |

#### Review

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| comment | string | A comment from the reviewer detailing the review. <br>*Example:* `""` | No |
| date | string | The date and time the review took place.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The identifier of the user that reviewed the vulnerability exception.<br>*Example:* `""` | No |
| user | integer | The login name of the user that reviewed the vulnerability exception.<br>*Example:* `""` | No |

#### RiskModifierSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| high | double | High critical adjustment modifier.<br>*Example:* `1.5` | No |
| low | double | Low critical adjustment modifier.<br>*Example:* `0.75` | No |
| medium | double | Medium critical adjustment modifier.<br>*Example:* `1` | No |
| veryHigh | double | Very high critical adjustment modifier.<br>*Example:* `2` | No |
| veryLow | double | Very low critical adjustment modifier.<br>*Example:* `0.5` | No |

#### RiskSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| adjustWithCriticality | boolean | Whether risk is adjusted using criticality tags.<br>*Example:* `true` | No |
| criticalityModifiers | [RiskModifierSettings](#riskmodifiersettings) | If `adjustWithCriticality` is enabled, details the risk modifiers by criticality tag.<br>*Example:* `""` | No |
| model | string | The risk model used to compute risk.<br>*Example:* `"real_risk"` | No |

#### RiskTrendAllAssetsResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| total | boolean | Includes a trend for the total risk of all assets.<br>*Example:* `true` | No |
| trend | string | Whether to include a trend for average risk of all assets or the total number of assets.<br>*Enum:* `"average-risk"`, `"number-of-assets"`, `"none"`<br>*Example:* `"average-risk"` | No |

#### RiskTrendResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| allAssets | [RiskTrendAllAssetsResource](#risktrendallassetsresource) | Trend settings for a trend across all assets in the scope of the report.<br>*Example:* `""` | No |
| assetGroupMembership | string | Whether all asset groups in the history of deployment or those as of the report generation time are to be included.<br>*Enum:* `"historical"`, `"generation"`<br>*Example:* `"historical"` | No |
| assetGroups | string | Whether to include a trend for the 5 highest-risk asset groups in the scope of the report (either the average or total risk). Only allowed if asset groups are specified in the report scope.<br>*Enum:* `"average"`, `"total"`<br>*Example:* `"total"` | No |
| assets | boolean | Whether to include a trend for the 5 highest-risk assets in the scope of the report.<br>*Example:* `true` | No |
| from | string | The start date of the risk trend, which can either be a duration or a specific date and time.<br>*Enum:* `"P1Y"`, `"P6M"`, `"P3M"`, `"P1M"`, `"<date>"`<br>*Example:* `"P3M"` | No |
| sites | string | Whether to include a trend for the 5 highest-risk sites in the scope of the report (either the average or total risk). Only allowed if sites are specified in the report scope.<br>*Enum:* `"average"`, `"total"`<br>*Example:* `"average"` | No |
| tagMembership | string | Whether all assets tagged in the history of deployment or those tagged as of the report generation time are to be included.<br>*Enum:* `"historical"`, `"generation"`<br>*Example:* `"historical"` | No |
| tags | string | Whether to include a trend for the 5 highest-risk tags for assets in the scope of the report (either the average or total risk). Only allowed if tags are specified in the report scope.<br>*Enum:* `"average"`, `"total"`<br>*Example:* `"average"` | No |
| to | string | The end date of the risk trend (empty if `from` is a duration).<br>*Example:* `""` | No |

#### Role

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| description | string | The description of the role.<br>*Example:* `""` | Yes |
| id | string | The identifier of the role.<br>*Example:* `""` | Yes |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The human readable name of the role.<br>*Example:* `""` | Yes |
| privileges | [ string ] | The privileges granted to the role. | No |

#### Scan

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | integer | The number of assets found in the scan.<br>*Example:* `""` | No |
| duration | string | The duration of the scan in ISO8601 format.<br>*Example:* `""` | No |
| endTime | string | The end time of the scan in ISO8601 format.<br>*Example:* `""` | No |
| engineId | integer | The identifier of the scan engine.<br>*Example:* `""` | No |
| engineIds | [ [EngineID](#engineid) ] | ${scan.engine.ids} | No |
| engineName | string | The name of the scan engine.<br>*Example:* `""` | No |
| id | long | The identifier of the scan.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The reason for the scan status.<br>*Example:* `""` | No |
| scanName | string | The user-driven scan name for the scan.<br>*Example:* `""` | No |
| scanType | string | The scan type (automated, manual, scheduled). <br>*Example:* `""` | No |
| startTime | string | The start time of the scan in ISO8601 format.<br>*Example:* `""` | No |
| startedBy | string | The name of the user that started the scan.<br>*Example:* `""` | No |
| startedByUsername | string | ${scan.username}<br>*Example:* `""` | No |
| status | string | The scan status.<br>*Enum:* `"aborted"`, `"unknown"`, `"running"`, `"finished"`, `"stopped"`, `"error"`, `"paused"`, `"dispatched"`, `"integrating"`<br>*Example:* `""` | No |
| vulnerabilities | [Vulnerabilities](#vulnerabilities) | The vulnerability synopsis of the scan.<br>*Example:* `""` | No |

#### ScanEngine

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| address | string | The address the scan engine is hosted.<br>*Example:* `"corporate-scan-engine-001.acme.com"` | Yes |
| contentVersion | string | The content version of the scan engine.<br>*Example:* `""` | No |
| id | integer | The identifier of the scan engine.<br>*Example:* `6` | No |
| isAWSPreAuthEngine | boolean | A boolean of whether the Engine is of type AWS Pre Authorized<br>*Example:* `false` | No |
| lastRefreshedDate | string | The date the engine was last refreshed. Date format is in ISO 8601.<br>*Example:* `""` | No |
| lastUpdatedDate | string | The date the engine was last updated. Date format is in ISO 8601.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the scan engine.<br>*Example:* `"Corporate Scan Engine 001"` | Yes |
| port | integer | The port used by the scan engine to communicate with the Security Console.<br>*Example:* `40894` | Yes |
| productVersion | string | The product version of the scan engine.<br>*Example:* `""` | No |
| serialNumber | string | ${scan.engine.serial.number<br>*Example:* `""` | No |
| sites | [ integer ] | A list of identifiers of each site the scan engine is assigned to. | No |
| status | string | The scan engine status. Can be one of the following values:  \| Value                     \| Description                                                                                \|  \| ------------------------- \| ------------------------------------------------------------------------------------------ \|  \| `"active"`                \| The scan engine is active.                                                                 \|  \| `"incompatible-version"`  \| The product version of the remote scan engine is not compatible with the Security Console. \|  \| `"not-responding"`        \| The scan engine is not responding to the Security Console.                                 \|  \| `"pending-authorization"` \| The Security Console is not yet authorized to connect to the scan engine.                  \|  \| `"unknown"`               \| The status of the scan engine is unknown.                                                  \|  <br>*Enum:* `"active"`, `"incompatible-version"`, `"not-responding"`, `"pending-authorization"`, `"unknown"`<br>*Example:* `""` | No |

#### ScanEvents

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| failed | boolean | Generates an alert when a scan fails. Default value is `false`.<br>*Example:* `false` | Yes |
| paused | boolean | Generates an alert when a scan pauses. Default value is `false`.<br>*Example:* `false` | Yes |
| resumed | boolean | Generates an alert when a scan resumes. Default value is `false`.<br>*Example:* `false` | No |
| started | boolean | Generates an alert when a scan starts. Default value is `false`.<br>*Example:* `false` | Yes |
| stopped | boolean | Generates an alert when a scan stops. Default value is `false`.<br>*Example:* `false` | Yes |

#### ScanSchedule

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [ScheduledScanTargets](#scheduledscantargets) | Allows one or more assets defined within the site to be scanned for this scan schedule. This property is only supported for static sites. When this property is `null`, or not defined in schedule, then all assets defined in the static site will be scanned.<br>*Example:* `""` | No |
| duration | string | Specifies the maximum duration the scheduled scan is allowed to run. Scheduled scans that do not complete within specified duration will be paused. The scan duration are represented by the format `"P[n]DT[n]H[n]M"`. In these representations, the [n] is replaced by a value for each of the date and time elements that follow the [n].The following table describes each supported value:  \| Value \| Description \|  \| ---------- \| ---------------- \|  \| P \| The duration designator. It must be placed at the start of the duration representation. \|  \| D \| The day designator that follows the value for the number of days. \|  \| T \| The time designator that precedes the time portion of the representation. \|  \| H \| The hour designator that follows the value for the number of hours. \|  \| M \| The minute designator that follows the value for the number of minutes. \|  For example, `"P5DT10H30M"` represents a duration of "5 days, 10 hours, and 30 minutes". Each duration designator is optional; however, at least one must be specified and it must be preceded by the `"P"` designator.  <br>*Example:* `""` | No |
| enabled | boolean | Flag indicating whether the scan schedule is enabled.<br>*Example:* `false` | Yes |
| id | integer | The identifier of the scan schedule.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| nextRuntimes | [ string ] | List the next 10 dates in the future the schedule will launch.  | No |
| onScanRepeat | string | Specifies the desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching is maximum duration. The following table describes each supported value:  \| Value \| Description \|  \| ---------- \| ---------------- \|  \| restart-scan \| Stops the previously-paused scan and launches a new scan if the previous scan did not complete within the specified duration. If the previous scheduled scan was not paused, then a new scan is launched. \|  \| resume-scan \| Resumes the previously-paused scan if the previous scan did not complete within the specified duration. If the previous scheduled scan was not paused, then a new scan is launched. \|  <br>*Example:* `""` | Yes |
| repeat | [Repeat](#repeat) | Settings for repeating a scheduled scan.<br>*Example:* `""` | No |
| scanEngineId | integer | The identifier of the scan engine to be used for this scan schedule. If not set, the site's assigned scan engine will be used.<br>*Example:* `""` | No |
| scanName | string | A user-defined name for the scan launched by the schedule. If not explicitly set in the schedule, the scan name will be generated prior to the scan launching. Scan names must be unique within the site's scan schedules.<br>*Example:* `""` | No |
| scanTemplateId | string | The identifier of the scan template to be used for this scan schedule. If not set, the site's assigned scan template will be used.<br>*Example:* `""` | No |
| start | string | The scheduled start date and time. Date is represented in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time.<br>*Example:* `"2018-03-01T04:31:56Z"` | Yes |

#### ScanScope

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | [StaticSite](#staticsite) | Specify assets to be included in site scans as well as assets to be excluded from site scans. If the property is defined, then at least one address or asset group must be specified for scanning. Property is required when creating a static site.<br>*Example:* `""` | No |
| connection | [DynamicSite](#dynamicsite) | Specify discovery connection settings for a dynamic site. Property is required when creating a dynamic site.<br>*Example:* `""` | No |

#### ScanSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| connectionTimeout | string | The connection timeout when establishing connections to remote scan engines, in ISO 8601 format. For example: `"PT15S"`.<br>*Example:* `"PT15S"` | No |
| incremental | boolean | Whether incremental scan results is enabled.<br>*Example:* `true` | No |
| maximumThreads | integer | The maximum number of scan threads to use in any scan. -1 means this is set by the scan template.<br>*Example:* `-1` | No |
| readTimeout | string | The read timeout when establishing connections to remote scan engines, in ISO 8601 format. For example: `"PT15M"`.<br>*Example:* `"PT15M"` | No |
| statusIdleTimeout | string | The idle timeout when checking the status of running scans, in ISO 8601 format. For example: `"PT3M"`.<br>*Example:* `"PT3M"` | No |
| statusThreads | integer | The number of threads to use when checking the status of running scans.<br>*Example:* `3` | No |

#### ScanSize

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| bytes | long | The raw value in bytes.<br>*Example:* `1370433223` | No |
| formatted | string | The value formatted in human-readable notation (e.g. GB, MB, KB, bytes).<br>*Example:* `"1.3 GB"` | No |

#### ScanTargetsResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| addresses | [ string ] | List of addresses. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ScanTemplate

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| checks | [ScanTemplateVulnerabilityChecks](#scantemplatevulnerabilitychecks) | Settings for which vulnerability checks to run during a scan. <br/>  The rules for inclusion of checks is as follows:  <ul>  <li>Enabled checks by category and by check type are included</li>  <li>Disabled checks in by category and by check type are removed</li>  <li>Enabled checks in by individual check are added (even if they are disabled in by category or check type)</li>  <li>Disabled checks in by individual check are removed</li>  <li>If unsafe is disabled, unsafe checks are removed</li>  <li>If potential is disabled, potential checks are removed</li>  <ul><br>*Example:* `""` | No |
| database | [ScanTemplateDatabase](#scantemplatedatabase) | Settings for discovery databases.<br>*Example:* `""` | No |
| description | string | A verbose description of the scan template..<br>*Example:* `"Performs a full network audit of all systems using only safe checks..."` | No |
| discovery | [ScanTemplateDiscovery](#scantemplatediscovery) | Discovery settings used during a scan.<br>*Example:* `""` | No |
| discoveryOnly | boolean | Whether only discovery is performed during a scan.<br>*Example:* `false` | No |
| enableWindowsServices | boolean | Whether Windows services are enabled during a scan. Windows services will be temporarily reconfigured when this option is selected. Original settings will be restored after the scan completes, unless it is interrupted.<br>*Example:* `false` | No |
| enhancedLogging | boolean | Whether enhanced logging is gathered during scanning. Collection of enhanced logs may greatly increase the disk space used by a scan.<br>*Example:* `false` | No |
| id | string | The identifier of the scan template<br>*Example:* `"full-audit-without-web-spider"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| maxParallelAssets | integer | The maximum number of assets scanned simultaneously per scan engine during a scan.<br>*Example:* `10` | No |
| maxScanProcesses | integer | The maximum number of scan processes simultaneously allowed against each asset during a scan.<br>*Example:* `10` | No |
| name | string | A concise name for the scan template.<br>*Example:* `"Full audit"` | No |
| policy | [Policy](#policy) | Policy configuration settings used during a scan.<br>*Example:* `""` | No |
| policyEnabled | boolean | Whether policy assessment is performed during a scan.<br>*Example:* `true` | No |
| telnet | [Telnet](#telnet) | Settings for interacting with the Telnet protocol.<br>*Example:* `""` | No |
| vulnerabilityEnabled | boolean | Whether vulnerability assessment is performed during a scan.<br>*Example:* `true` | No |
| web | [ScanTemplateWebSpider](#scantemplatewebspider) | Web spider settings used during a scan.<br>*Example:* `""` | No |
| webEnabled | boolean | Whether web spidering and assessment are performed during a scan.<br>*Example:* `true` | No |

#### ScanTemplateAssetDiscovery

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| collectWhoisInformation | boolean | Whether to query Whois during discovery. Defaults to `false`.<br>*Example:* `false` | No |
| fingerprintMinimumCertainty | double | The minimum certainty required for a fingerprint to be considered valid during a scan. Defaults to `0.16`.<br>*Example:* `0.16` | No |
| fingerprintRetries | integer | The number of fingerprinting attempts made to determine the operating system fingerprint. Defaults to `4`.<br>*Example:* `0` | No |
| ipFingerprintingEnabled | boolean | Whether to fingerprint TCP/IP stacks for hardware, operating system and software information.<br>*Example:* `true` | No |
| sendArpPings | boolean | Whether ARP pings are sent during asset discovery. Defaults to `true`.<br>*Example:* `true` | No |
| sendIcmpPings | boolean | Whether ICMP pings are sent during asset discovery. Defaults to `false`.<br>*Example:* `true` | No |
| tcpPorts | [ integer ] | TCP ports to send packets and perform discovery. Defaults to no ports. | No |
| treatTcpResetAsAsset | boolean | Whether TCP reset responses are treated as live assets. Defaults to `true`.<br>*Example:* `true` | No |
| udpPorts | [ integer ] | UDP ports to send packets and perform discovery. Defaults to no ports. | No |

#### ScanTemplateDatabase

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| db2 | string | Database name for DB2 database instance.<br>*Example:* `"database"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| oracle | [ string ] | Database name (SID) for an Oracle database instance.<br>*Example:* `"default"` | No |
| postgres | string | Database name for PostgesSQL database instance.<br>*Example:* `"postgres"` | No |

#### ScanTemplateDiscovery

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| asset | [ScanTemplateAssetDiscovery](#scantemplateassetdiscovery) | Asset discovery settings used during a scan.<br>*Example:* `""` | No |
| performance | [ScanTemplateDiscoveryPerformance](#scantemplatediscoveryperformance) | Discovery performance settings used during a scan.<br>*Example:* `""` | No |
| service | [ScanTemplateServiceDiscovery](#scantemplateservicediscovery) | Service discovery settings used during a scan.<br>*Example:* `""` | No |

#### ScanTemplateDiscoveryPerformance

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| packetRate | [ScanTemplateDiscoveryPerformancePacketsRate](#scantemplatediscoveryperformancepacketsrate) | The number of packets to send per second during scanning.<br>*Example:* `""` | No |
| parallelism | [ScanTemplateDiscoveryPerformanceParallelism](#scantemplatediscoveryperformanceparallelism) | The number of discovery connection requests to be sent to target host simultaneously. These settings has no effect if values have been set for `scanDelay`.<br>*Example:* `""` | No |
| retryLimit | integer | The maximum number of attempts to contact target assets. If the limit is exceeded with no response, the given asset is not scanned. Defaults to `3`.<br>*Example:* `3` | No |
| scanDelay | [ScanTemplateDiscoveryPerformanceScanDelay](#scantemplatediscoveryperformancescandelay) | The duration to wait between sending packets to each target host during a scan.<br>*Example:* `""` | No |
| timeout | [ScanTemplateDiscoveryPerformanceTimeout](#scantemplatediscoveryperformancetimeout) | The duration to wait between retry attempts.<br>*Example:* `""` | No |

#### ScanTemplateDiscoveryPerformancePacketsRate

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| defeatRateLimit | boolean | Whether defeat rate limit (defeat-rst-ratelimit) is enforced on the minimum packet setting, which can improve scan speed. If it is disabled, the minimum packet rate setting may be ignored when a target limits its rate of RST (reset) responses to a port scan. This can increase scan accuracy by preventing the scan from missing ports. Defaults to `true`.<br>*Example:* `true` | No |
| maximum | integer | The minimum number of packets to send each second during discovery attempts. Defaults to `0`.<br>*Example:* `15000` | No |
| minimum | integer | The minimum number of packets to send each second during discovery attempts. Defaults to `0`.<br>*Example:* `450` | No |

#### ScanTemplateDiscoveryPerformanceParallelism

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| maximum | integer | The maximum number of discovery connection requests send in parallel. Defaults to `0`.<br>*Example:* `0` | No |
| minimum | integer | The minimum number of discovery connection requests send in parallel. Defaults to `0`.<br>*Example:* `0` | No |

#### ScanTemplateDiscoveryPerformanceScanDelay

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| maximum | string | The minimum duration to wait between sending packets to each target host. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P30S` (30s). Defaults to `PT0S`.<br>*Example:* `"PT0S"` | No |
| minimum | string | The maximum duration to wait between sending packets to each target host. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P30S` (30s). Defaults to `PT0S`.<br>*Example:* `"PT0S"` | No |

#### ScanTemplateDiscoveryPerformanceTimeout

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| initial | string | The initial timeout to wait between retry attempts. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT0.5S`.<br>*Example:* `"PT0.5S"` | No |
| maximum | string | The maximum time to wait between retries. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT3S`.<br>*Example:* `"PT3S"` | No |
| minimum | string | The minimum time to wait between retries. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT0.5S`.<br>*Example:* `"PT0S"` | No |

#### ScanTemplateServiceDiscovery

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| serviceNameFile | string | An optional file that lists each port and the service that commonly resides on it. If scans cannot identify actual services on ports, service names will be derived from this file in scan results. Defaults to empty.<br>*Example:* `""` | No |
| tcp | [ScanTemplateServiceDiscoveryTcp](#scantemplateservicediscoverytcp) | TCP service discovery settings.<br>*Example:* `""` | No |
| udp | [ScanTemplateServiceDiscoveryUdp](#scantemplateservicediscoveryudp) | UDP service discovery settings.<br>*Example:* `""` | No |

#### ScanTemplateServiceDiscoveryTcp

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| additionalPorts | [ object ] | Additional TCP ports to scan. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.<br>*Example:* `"3078,8000-8080"` | No |
| excludedPorts | [ object ] | TCP ports to exclude from scanning. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.<br>*Example:* `"1024"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| method | string | The method of TCP discovery. Defaults to `SYN`.<br>*Enum:* `"SYN"`, `"SYN+RST"`, `"SYN+FIN"`, `"SYN+ECE"`, `"Full"`<br>*Example:* `"SYN"` | No |
| ports | string | The TCP ports to scan. Defaults to `well-known`.<br>*Enum:* `"all"`, `"well-known"`, `"custom"`, `"none"`<br>*Example:* `"well-known"` | No |

#### ScanTemplateServiceDiscoveryUdp

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| additionalPorts | [ object ] | Additional UDP ports to scan. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.<br>*Example:* `"4020-4032"` | No |
| excludedPorts | [ object ] | UDP ports to exclude from scanning. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.<br>*Example:* `"9899"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| ports | string | The UDP ports to scan. Defaults to `well-known`.<br>*Enum:* `"all"`, `"well-known"`, `"custom"`, `"none"`<br>*Example:* `"well-known"` | No |

#### ScanTemplateVulnerabilityCheckCategories

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| disabled | [ string ] | The categories of vulnerability checks to disable during a scan. | No |
| enabled | [ string ] | The categories of vulnerability checks to enable during a scan. | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ScanTemplateVulnerabilityCheckIndividual

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| disabled | [ string ] | The individual vulnerability checks to disable during a scan. | No |
| enabled | [ string ] | The individual vulnerability checks to enable during a scan. | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### ScanTemplateVulnerabilityChecks

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| categories | [ScanTemplateVulnerabilityCheckCategories](#scantemplatevulnerabilitycheckcategories) | The vulnerability check categories enabled or disabled during a scan.<br>*Example:* `""` | No |
| correlate | boolean | Whether an extra step is performed at the end of the scan where more trust is put in OS patch checks to attempt to override the results of other checks which could be less reliable.<br>*Example:* `false` | No |
| individual | [ScanTemplateVulnerabilityCheckIndividual](#scantemplatevulnerabilitycheckindividual) | The individual vulnerability checks enabled or disabled during a scan.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| potential | boolean | Whether checks that result in potential vulnerabilities are assessed during a scan.<br>*Example:* `false` | No |
| types | [VulnerabilityCheckType](#vulnerabilitychecktype) | The vulnerability check types enabled or disabled during a scan.<br>*Example:* `""` | No |
| unsafe | boolean | Whether checks considered "unsafe" are assessed during a scan.<br>*Example:* `false` | No |

#### ScanTemplateWebSpider

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| dontScanMultiUseDevices | boolean | Whether scanning of multi-use devices, such as printers or print servers should be avoided.<br>*Example:* `true` | No |
| includeQueryStrings | boolean | Whether query strings are using in URLs when web spidering. This causes the web spider to make many more requests to the Web server. This will increase overall scan time and possibly affect the Web server's performance for legitimate users.<br>*Example:* `false` | No |
| paths | [ScanTemplateWebSpiderPaths](#scantemplatewebspiderpaths) | Paths to use when web spidering.<br>*Example:* `""` | No |
| patterns | [ScanTemplateWebSpiderPatterns](#scantemplatewebspiderpatterns) | Patterns to match responses during web spidering.<br>*Example:* `""` | No |
| performance | [ScanTemplateWebSpiderPerformance](#scantemplatewebspiderperformance) | Performance settings used during web spidering.<br>*Example:* `""` | No |
| testCommonUsernamesAndPasswords | boolean | Whether to determine if discovered logon forms accept commonly used user names or passwords. The process may cause authentication services with certain security policies to lock out accounts with these credentials.<br>*Example:* `false` | No |
| testXssInSingleScan | boolean | Whether to test for persistent cross-site scripting during a single scan. This test helps to reduce the risk of dangerous attacks via malicious code stored on Web servers. Enabling it may increase Web spider scan times.<br>*Example:* `false` | No |
| userAgent | string | The `User-Agent` to use when web spidering. Defaults to `"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"`.<br>*Example:* `"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"` | No |

#### ScanTemplateWebSpiderPaths

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| boostrap | string | Paths to bootstrap spidering with.<br>*Example:* `"/root"` | No |
| excluded | string | Paths excluded from spidering.<br>*Example:* `"/root/sensitive.html"` | No |
| honorRobotDirectives | boolean | Whether to honor robot directives.<br>*Example:* `false` | No |

#### ScanTemplateWebSpiderPatterns

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| sensitiveContent | string | A regular expression that is used to find sensitive content on a page.<br>*Example:* `""` | No |
| sensitiveField | string | A regular expression that is used to find fields that may contain sensitive input. Defaults to `"(p\|pass)(word\|phrase\|wd\|code)"`.<br>*Example:* `"(p|pass)(word|phrase|wd|code)"` | No |

#### ScanTemplateWebSpiderPerformance

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| httpDaemonsToSkip | [ string ] | The names of HTTP Daemons (HTTPd) to skip when spidering. For example, `"CUPS"`. | No |
| maximumDirectoryLevels | integer | The directory depth limit for web spidering. Limiting directory depth can save significant time, especially with large sites. A value of `0` signifies unlimited directory traversal. Defaults to `6`.<br>*Example:* `6` | No |
| maximumForeignHosts | integer | The maximum number of unique host names that the spider may resolve. This function adds substantial time to the spidering process, especially with large Web sites, because of frequent cross-link checking involved. Defaults to `100`.<br>*Example:* `100` | No |
| maximumLinkDepth | integer | The maximum depth of links to traverse when spidering. Defaults to `6`.<br>*Example:* `6` | No |
| maximumPages | integer | The maximum the number of pages that are spidered. This is a time-saving measure for large sites. Defaults to `3000`.<br>*Example:* `3000` | No |
| maximumRetries | integer | The maximum the number of times to retry a request after a failure. A value of `0` means no retry attempts are made. Defaults to `2`.<br>*Example:* `2` | No |
| maximumTime | string | The maximum length of time to web spider. This limit prevents scans from taking longer than the allotted scan schedule. A value of `PT0S` means no limit is applied. The acceptable range is `PT1M` to `PT16666.6667H`.<br>*Example:* `"PT0S"` | No |
| responseTimeout | string | The duration to wait for a response from a target web server. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P1H` (1 hour). Defaults to `PT2M`.<br>*Example:* `"PT2M"` | No |
| threadsPerServer | integer | The number of threads to use per web server being spidered. Defaults to `3`.<br>*Example:* `3` | No |

#### ScheduledScanTargets

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| excludedAssetGroups | [ExcludedAssetGroups](#excludedassetgroups) | Assets associated with these asset groups will be excluded from the site's scan.<br>*Example:* `""` | No |
| excludedTargets | [ExcludedScanTargets](#excludedscantargets) | Addresses to be excluded from the site's scan. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.<br>*Example:* `""` | No |
| includedAssetGroups | [IncludedAssetGroups](#includedassetgroups) | Allows users to specify a subset of the site's included asset groups to be included in the scan. If the property is defined, then at least one valid already defined as an included asset group must be specified.<br>*Example:* `""` | No |
| includedTargets | [IncludedScanTargets](#includedscantargets) | Allows users to specify a subset of the site's scan targets to be included in the scan. If the property is defined, then at least one address must be specified.<br>*Example:* `""` | No |

#### SearchCriteria

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| filters | [ [SwaggerSearchCriteriaFilter](#swaggersearchcriteriafilter) ] | Filters used to match assets. See <a href="#section/Responses/SearchCriteria">Search Criteria</a> for more information on the structure and format. | No |
| match | string | Operator to determine how to match filters. `all` requires that all filters match for an asset to be included. `any` requires only one filter to match for an asset to be included.<br>*Enum:* `"any"`, `"all"`<br>*Example:* `"all"` | No |

#### Service

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| configurations | [ [Configuration](#configuration) ] | Configuration key-values pairs enumerated on the service. | No |
| databases | [ [Database](#database) ] | The databases enumerated on the service. | No |
| family | string | The family of the service.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the service.<br>*Example:* `"CIFS Name Service"` | No |
| port | integer | The port of the service.<br>*Example:* `139` | Yes |
| product | string | The product running the service.<br>*Example:* `"Samba"` | No |
| protocol | string | The protocol of the service.<br>*Enum:* `"ip"`, `"icmp"`, `"igmp"`, `"ggp"`, `"tcp"`, `"pup"`, `"udp"`, `"idp"`, `"esp"`, `"nd"`, `"raw"`<br>*Example:* `"tcp"` | Yes |
| userGroups | [ [GroupAccount](#groupaccount) ] | The group accounts enumerated on the service. | No |
| users | [ [UserAccount](#useraccount) ] | The user accounts enumerated on the service. | No |
| vendor | string | The vendor of the service.<br>*Example:* `""` | No |
| version | string | The version of the service.<br>*Example:* `"3.5.11"` | No |
| webApplications | [ [WebApplication](#webapplication) ] | The web applications found on the service. | No |

#### ServiceLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| href | string | A hypertext reference, which is either a URI (see <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>) or URI template (see <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc6570">RFC 6570</a>). <br>*Example:* `"https://hostname:3780/api/3/..."` | No |
| port | integer | The port of the service.<br>*Example:* `22` | No |
| protocol | string | The protocol of the service.<br>*Enum:* `"ip"`, `"icmp"`, `"igmp"`, `"ggp"`, `"tcp"`, `"pup"`, `"udp"`, `"idp"`, `"esp"`, `"nd"`, `"raw"`<br>*Example:* `"tcp"` | No |
| rel | string | The link relation type. This value is one from the <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc5988#section-6.2">Link Relation Type Registry</a> or is the type of resource being linked to.<br>*Example:* `"Service"` | No |

#### ServiceUnavailableError

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"503"`<br>*Example:* `"503"` | Yes |

#### Settings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assetLinking | boolean | Whether asset linking is enabled.<br>*Example:* `true` | No |
| authentication | [AuthenticationSettings](#authenticationsettings) | Details the authentication settings.<br>*Example:* `""` | No |
| database | [DatabaseSettings](#databasesettings) | Details the database settings.<br>*Example:* `""` | No |
| directory | string | The root directory of the console.<br>*Example:* `"/opt/rapid7/nexpose"` | No |
| insightPlatform | boolean | Whether the usage of the Insight platform is enabled.<br>*Example:* `true` | No |
| insightPlatformRegion | string | The region used for the Insight platform, if enabled.<br>*Example:* `"us-east-1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| risk | [RiskSettings](#risksettings) | Details risk configuration and settings.<br>*Example:* `""` | No |
| scan | [ScanSettings](#scansettings) | Details the global settings for scanning.<br>*Example:* `""` | No |
| serialNumber | string | The console serial number.<br>*Example:* `"729F31B1C92F3C91DFA8A649F4D5C883C269BD45"` | No |
| smtp | [SmtpSettings](#smtpsettings) | Global SMTP distribution settings.<br>*Example:* `""` | No |
| updates | [UpdateSettings](#updatesettings) | Details the update settings.<br>*Example:* `""` | No |
| uuid | string | The universally unique identifier (UUID) of the console.<br>*Example:* `"7231036a-e052-11e7-80c1-9a214cf093ae"` | No |
| web | [WebSettings](#websettings) | Details the web server settings.<br>*Example:* `""` | No |

#### SharedCredential

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| account | [SharedCredentialAccount](#sharedcredentialaccount) | Specify the type of service to authenticate as well as all of the information required by that service. <div class="properties">  <div class="property-info">  <span class="property-name">service</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"as400"</span>  <span class="param-enum-value string">"cifs"</span>  <span class="param-enum-value string">"cifshash"</span>  <span class="param-enum-value string">"cvs"</span>  <span class="param-enum-value string">"db2"</span>  <span class="param-enum-value string">"ftp"</span>  <span class="param-enum-value string">"http"</span>  <span class="param-enum-value string">"ms-sql"</span>  <span class="param-enum-value string">"mysql"</span>  <span class="param-enum-value string">"notes"</span>  <span class="param-enum-value string">"oracle"</span>  <span class="param-enum-value string">"oracle-service-name"</span>  <span class="param-enum-value string">"pop"</span>  <span class="param-enum-value string">"postgresql"</span>  <span class="param-enum-value string">"remote-exec"</span>  <span class="param-enum-value string">"snmp"</span>  <span class="param-enum-value string">"snmpv3"</span>  <span class="param-enum-value string">"ssh"</span>  <span class="param-enum-value string">"ssh-key"</span>  <span class="param-enum-value string">"sybase"</span>  <span class="param-enum-value string">"telnet"</span>  <span class="param-enum-value string">"kerberos"</span>  </div>  <div class="redoc-markdown-block">The type of service to authenticate with.</div> </div>  </div>  The following are the names of the valid values for service:  \| Value         \| Service                                         \|  \| ------------- \| ----------------------------------------------- \|  \| `as400`       \| IBM AS/400                                      \|  \| `cifs`        \| Microsoft Windows/Samba (SMB/CIFS)              \|  \| `cifshash`    \| Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS) \|  \| `cvs`         \| Concurrent Versioning System (CVS)              \|  \| `db2`         \| DB2                                             \|  \| `ftp`         \| File Transfer Protocol (FTP)                    \|  \| `http`        \| Web Site HTTP Authentication                    \|  \| `ms-sql`      \| Microsoft SQL Server                            \|  \| `mysql`       \| MySQL Server                                    \|  \| `notes`       \| Lotus Notes/Domino                              \|  \| `oracle`      \| Oracle                                          \|  \| `oracle-service-name`      \| Oracle Service Name                  \|  \| `pop`         \| Post Office Protocol (POP)                      \|  \| `postgresql`  \| PostgreSQL                                      \|  \| `remote-exec` \| Remote Execution                                \|  \| `snmp`        \| Simple Network Management Protocol v1/v2c       \|  \| `snmpv3`      \| Simple Network Management Protocol v3           \|  \| `ssh`         \| Secure Shell (SSH)                              \|  \| `ssh-key`     \| Secure Shell (SSH) Public Key                   \|  \| `sybase`      \| Sybase SQL Server                               \|  \| `telnet`      \| Telnet                                          \|  \| `kerberos`    \| Kerberos                                        \|   <p>The following is a specification of supported credential properties for each type of service. These properties are to be specified within the <code>account</code> object.</p>  `as400` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cifs` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cifshash` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">ntlmHash</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The NTLM password hash. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cvs` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `db2` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `ftp` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `http` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">realm</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The realm.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `ms-sql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">useWindowsAuthentication</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag signaling whether to connect to the database using Windows authentication. When set to <code>true</code>, Windows authentication is attempted; when set to <code>false</code>, SQL authentication is attempted.</p> </div> </div>  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain. This property cannot be specified unless property <code>useWindowsAuthentication</code> is set to <code>true</code>.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `mysql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The Notes ID password. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `notes` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">notesIDPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `oracle` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">sid</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">enumerateSids</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag instructing the scan engine to attempt to enumerate SIDs from your environment. If set to <code>true</code>, set the Oracle Net Listener password in property <code>oracleListenerPassword</code>.</p> </div> </div>  <div class="property-info">  <span class="property-name">oracleListenerPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The Oracle Net Listener password. Used to enumerate SIDs from your environment.</p></div> </div>  </div>  `oracle-service-name` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">serviceName</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The service name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `pop` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `postgresql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `remote-exec` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `snmp` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">communityName</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The community name that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `snmpv3` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">authenticationType</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"no-authentication"</span>  <span class="param-enum-value string">"md5"</span>  <span class="param-enum-value string">"sha"</span>  </div>  <div class="redoc-markdown-block"><p>The authentication protocols available to use in SNMP v3.</p></div> </div> <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account that will be used for authenticating. Is required when the property <code>authenticationType</code> is set to valid value other than <code>"no-authentication"</code>. <strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  <div class="property-info">  <span class="property-name">privacyType</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"no-privacy"</span>  <span class="param-enum-value string">"des"</span>  <span class="param-enum-value string">"aes-128"</span>  <span class="param-enum-value string">"aes-192"</span>  <span class="param-enum-value string">"aes-192-with-3-des-key-extension"</span>  <span class="param-enum-value string">"aes-256"</span>  <span class="param-enum-value string">"aes-265-with-3-des-key-extension"</span>  </div>  <div class="redoc-markdown-block"><p>The privacy protocols available to use in SNMP v3.</p></div> </div> <div class="property-info">  <span class="property-name">privacyPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The privacy password for the account that will be used for authenticating. Is required when the property <code>authenticationType</code> is set to valid value other than <code>"no-authentication"</code> and when the <code>privacyType</code> is set to a valid value other than code>"no-privacy"</code>. <strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `ssh` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">permissionElevation</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"none"</span>  <span class="param-enum-value string">"sudo"</span>  <span class="param-enum-value string">"sudosu"</span>  <span class="param-enum-value string">"su"</span>  <span class="param-enum-value string">"pbrun"</span>  <span class="param-enum-value string">"privileged-exec"</span>  </div>  <div class="redoc-markdown-block"> <p> Elevate scan engine permissions to administrative or root access, which is necessary to obtain certain data during the scan. Defaults to <code>"none"</code> if not specified. </p> </div> </div> <div class="property-info">  <span class="property-name">permissionElevationUsername</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The user name for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.</p> </div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.<strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `ssh-key` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">privateKeyPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for private key. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">pemKey</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The PEM-format private key. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">permissionElevation</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"none"</span>  <span class="param-enum-value string">"sudo"</span>  <span class="param-enum-value string">"sudosu"</span>  <span class="param-enum-value string">"su"</span>  <span class="param-enum-value string">"pbrun"</span>  <span class="param-enum-value string">"privileged-exec"</span>  </div>  <div class="redoc-markdown-block"> <p> Elevate scan engine permissions to administrative or root access, which is necessary to obtain certain data during the scan. Defaults to <code>"none"</code> if not specified. </p> </div> </div> <div class="property-info">  <span class="property-name">permissionElevationUsername</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The user name for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.</p> </div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.<strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `sybase` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">useWindowsAuthentication</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag signaling whether to connect to the database using Windows authentication. When set to <code>true</code>, Windows authentication is attempted; when set to <code>false</code>, SQL authentication is attempted.</p> </div> </div>  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain. This property cannot be specified unless property <code>useWindowsAuthentication</code> is set to <code>true</code>.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `telnet` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `kerberos` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  <br>*Example:* `""` | Yes |
| description | string | The description of the credential.<br>*Example:* `""` | No |
| hostRestriction | string | The host name or IP address that you want to restrict the credentials to.<br>*Example:* `""` | No |
| id | integer | The identifier of the credential.<br>*Example:* `""` | No |
| name | string | The name of the credential.<br>*Example:* `""` | Yes |
| portRestriction | integer | Further restricts the credential to attempt to authenticate on a specific port. <br>*Example:* `""` | No |
| siteAssignment | string | Assigns the shared scan credential either to be available to all sites or to a specific list of sites. The following table describes each supported value:  \| Value \| Description \|  \| ---------- \| ---------------- \|  \| `"all-sites"` \| The shared scan credential is assigned to all current and future sites. \|  \| `"specific-sites"` \| The shared scan credential is assigned to zero sites by default. Administrators must explicitly assign sites to the shared credential. \|  Shared scan credentials assigned to a site can disabled within the site configuration, if needed.<br>*Example:* `""` | Yes |
| sites | [ integer ] | List of site identifiers. These sites are explicitly assigned access to the shared scan credential, allowing the site to use the credential for authentication during a scan. This property can only be set if the value of property `siteAssignment` is set to `"specific-sites"`. When the property `siteAssignment` is set to `"all-sites"`, this property will be `null`. | No |

#### SharedCredentialAccount

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| authenticationType | string |  | No |
| communityName | string |  | No |
| database | string |  | No |
| domain | string |  | No |
| enumerateSids | boolean |  | No |
| notesIDPassword | string |  | No |
| ntlmHash | string |  | No |
| oracleListenerPassword | string |  | No |
| password | string |  | No |
| pemKey | string |  | No |
| permissionElevation | string |  | No |
| permissionElevationPassword | string |  | No |
| permissionElevationUsername | string |  | No |
| privacyPassword | string |  | No |
| privacyType | string |  | No |
| privateKeyPassword | string |  | No |
| realm | string |  | No |
| service | string |  | No |
| serviceName | string |  | No |
| sid | string |  | No |
| useWindowsAuthentication | boolean |  | No |
| username | string |  | No |

#### Site

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| assets | integer | The number of assets that belong to the site.<br>*Example:* `768` | No |
| connectionType | string | The type of discovery connection configured for the site. This property only applies to dynamic sites.<br>*Enum:* `"activesync-ldap"`, `"activesync-office365"`, `"activesync-powershell"`, `"aws"`, `"dhcp"`, `"sonar"`, `"vsphere"`<br>*Example:* `""` | No |
| description | string | The site description.<br>*Example:* `""` | No |
| id | integer | The identifier of the site.<br>*Example:* `""` | No |
| importance | string | The site importance.<br>*Example:* `""` | No |
| lastScanTime | string | The date and time of the site's last scan.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The site name.<br>*Example:* `""` | No |
| riskScore | double | The risk score (with criticality adjustments) of the site.<br>*Example:* `4457823.78` | No |
| scanEngine | integer | The identifier of the scan engine configured in the site.<br>*Example:* `""` | No |
| scanTemplate | string | The identifier of the scan template configured in the site.<br>*Example:* `""` | No |
| type | string | The type of the site.<br>*Enum:* `"agent"`, `"dynamic"`, `"static"`<br>*Example:* `""` | No |
| vulnerabilities | [Vulnerabilities](#vulnerabilities) | Summary information for distinct vulnerabilities found on the assets.<br>*Example:* `""` | No |

#### SiteCreateResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| description | string | The site's description.<br>*Example:* `""` | No |
| engineId | integer | The identifier of a scan engine. Default scan engine is selected when not specified.<br>*Example:* `""` | No |
| importance | string | The site importance. Defaults to `"normal"` if not specified.<br>*Enum:* `"very_low"`, `"low"`, `"normal"`, `"high"`, `"very_high"`<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The site name. Name must be unique.<br>*Example:* `""` | Yes |
| scan | [ScanScope](#scanscope) | Defines the scope of scan targets for the site, which can be addresses, or asset groups, for static sites and a discovery configuration for dynamic sites. Only one property must be set by the user when saving a site.<br>*Example:* `""` | No |
| scanTemplateId | string | The identifier of a scan template. Default scan template is selected when not specified.<br>*Example:* `""` | No |

#### SiteCredential

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| account | [Account](#account) | Specify the type of service to authenticate as well as all of the information required by that service. <div class="properties">  <div class="property-info">  <span class="property-name">service</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"as400"</span>  <span class="param-enum-value string">"cifs"</span>  <span class="param-enum-value string">"cifshash"</span>  <span class="param-enum-value string">"cvs"</span>  <span class="param-enum-value string">"db2"</span>  <span class="param-enum-value string">"ftp"</span>  <span class="param-enum-value string">"http"</span>  <span class="param-enum-value string">"ms-sql"</span>  <span class="param-enum-value string">"mysql"</span>  <span class="param-enum-value string">"notes"</span>  <span class="param-enum-value string">"oracle"</span>  <span class="param-enum-value string">"oracle-service-name"</span>  <span class="param-enum-value string">"pop"</span>  <span class="param-enum-value string">"postgresql"</span>  <span class="param-enum-value string">"remote-exec"</span>  <span class="param-enum-value string">"snmp"</span>  <span class="param-enum-value string">"snmpv3"</span>  <span class="param-enum-value string">"ssh"</span>  <span class="param-enum-value string">"ssh-key"</span>  <span class="param-enum-value string">"sybase"</span>  <span class="param-enum-value string">"telnet"</span>  <span class="param-enum-value string">"kerberos"</span>  </div>  <div class="redoc-markdown-block">The type of service to authenticate with.</div> </div>  </div>  The following are the names of the valid values for service:  \| Value         \| Service                                         \|  \| ------------- \| ----------------------------------------------- \|  \| `as400`       \| IBM AS/400                                      \|  \| `cifs`        \| Microsoft Windows/Samba (SMB/CIFS)              \|  \| `cifshash`    \| Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS) \|  \| `cvs`         \| Concurrent Versioning System (CVS)              \|  \| `db2`         \| DB2                                             \|  \| `ftp`         \| File Transfer Protocol (FTP)                    \|  \| `http`        \| Web Site HTTP Authentication                    \|  \| `ms-sql`      \| Microsoft SQL Server                            \|  \| `mysql`       \| MySQL Server                                    \|  \| `notes`       \| Lotus Notes/Domino                              \|  \| `oracle`      \| Oracle                                          \|  \| `oracle-service-name`      \| Oracle Service Name                  \|  \| `pop`         \| Post Office Protocol (POP)                      \|  \| `postgresql`  \| PostgreSQL                                      \|  \| `remote-exec` \| Remote Execution                                \|  \| `snmp`        \| Simple Network Management Protocol v1/v2c       \|  \| `snmpv3`      \| Simple Network Management Protocol v3           \|  \| `ssh`         \| Secure Shell (SSH)                              \|  \| `ssh-key`     \| Secure Shell (SSH) Public Key                   \|  \| `sybase`      \| Sybase SQL Server                               \|  \| `telnet`      \| Telnet                                          \|  \| `kerberos`    \| Kerberos                                        \|   <p>The following is a specification of supported credential properties for each type of service. These properties are to be specified within the <code>account</code> object.</p>  `as400` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cifs` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cifshash` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">ntlmHash</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The NTLM password hash. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `cvs` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `db2` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `ftp` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `http` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">realm</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The realm.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `ms-sql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">useWindowsAuthentication</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag signaling whether to connect to the database using Windows authentication. When set to <code>true</code>, Windows authentication is attempted; when set to <code>false</code>, SQL authentication is attempted.</p> </div> </div>  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain. This property cannot be specified unless property <code>useWindowsAuthentication</code> is set to <code>true</code>.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `mysql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The Notes ID password. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `notes` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">notesIDPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `oracle` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">sid</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">enumerateSids</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag instructing the scan engine to attempt to enumerate SIDs from your environment. If set to <code>true</code>, set the Oracle Net Listener password in property <code>oracleListenerPassword</code>.</p> </div> </div>  <div class="property-info">  <span class="property-name">oracleListenerPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The Oracle Net Listener password. Used to enumerate SIDs from your environment.</p></div> </div>  </div>  `oracle-service-name` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">serviceName</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The service name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `pop` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `postgresql` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `remote-exec` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `snmp` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">communityName</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The community name that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `snmpv3` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">authenticationType</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"no-authentication"</span>  <span class="param-enum-value string">"md5"</span>  <span class="param-enum-value string">"sha"</span>  </div>  <div class="redoc-markdown-block"><p>The authentication protocols available to use in SNMP v3.</p></div> </div> <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account that will be used for authenticating. Is required when the property <code>authenticationType</code> is set to valid value other than <code>"no-authentication"</code>. <strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  <div class="property-info">  <span class="property-name">privacyType</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"no-privacy"</span>  <span class="param-enum-value string">"des"</span>  <span class="param-enum-value string">"aes-128"</span>  <span class="param-enum-value string">"aes-192"</span>  <span class="param-enum-value string">"aes-192-with-3-des-key-extension"</span>  <span class="param-enum-value string">"aes-256"</span>  <span class="param-enum-value string">"aes-265-with-3-des-key-extension"</span>  </div>  <div class="redoc-markdown-block"><p>The privacy protocols available to use in SNMP v3.</p></div> </div> <div class="property-info">  <span class="property-name">privacyPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The privacy password for the account that will be used for authenticating. Is required when the property <code>authenticationType</code> is set to valid value other than <code>"no-authentication"</code> and when the <code>privacyType</code> is set to a valid value other than code>"no-privacy"</code>. <strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `ssh` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">permissionElevation</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"none"</span>  <span class="param-enum-value string">"sudo"</span>  <span class="param-enum-value string">"sudosu"</span>  <span class="param-enum-value string">"su"</span>  <span class="param-enum-value string">"pbrun"</span>  <span class="param-enum-value string">"privileged-exec"</span>  </div>  <div class="redoc-markdown-block"> <p> Elevate scan engine permissions to administrative or root access, which is necessary to obtain certain data during the scan. Defaults to <code>"none"</code> if not specified. </p> </div> </div> <div class="property-info">  <span class="property-name">permissionElevationUsername</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The user name for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.</p> </div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.<strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `ssh-key` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">privateKeyPassword</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for private key. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">pemKey</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The PEM-format private key. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  <div class="property-info">  <span class="property-name">permissionElevation</span> <span class="param-type">string</span>  <div class="param-enum">  <span class="param-enum-value string">"none"</span>  <span class="param-enum-value string">"sudo"</span>  <span class="param-enum-value string">"sudosu"</span>  <span class="param-enum-value string">"su"</span>  <span class="param-enum-value string">"pbrun"</span>  <span class="param-enum-value string">"privileged-exec"</span>  </div>  <div class="redoc-markdown-block"> <p> Elevate scan engine permissions to administrative or root access, which is necessary to obtain certain data during the scan. Defaults to <code>"none"</code> if not specified. </p> </div> </div> <div class="property-info">  <span class="property-name">permissionElevationUsername</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The user name for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.</p> </div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"> <p> The password for the account with elevated permissions. This property must not be specified when the property <code>permissionElevation</code> is set to either <code>"none"</code> or <code>"pbrun"</code>; otherwise the property is required.<strong>Note: This property is not returned in responses for security.</strong></p> </div> </div>  </div>  `sybase` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">database</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The name of the database. If not specified, a default database name will be used during authentication.</p></div> </div>  <div class="property-info">  <span class="property-name">useWindowsAuthentication</span> <span class="param-type">boolean</span>  <div class="redoc-markdown-block"> <p> Boolean flag signaling whether to connect to the database using Windows authentication. When set to <code>true</code>, Windows authentication is attempted; when set to <code>false</code>, SQL authentication is attempted.</p> </div> </div>  <div class="property-info">  <span class="property-name">domain</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The address of the domain. This property cannot be specified unless property <code>useWindowsAuthentication</code> is set to <code>true</code>.</p></div> </div>  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `telnet` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  `kerberos` supported properties: <div class="properties">  <div class="property-info">  <span class="property-name">username</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The user name for the account that will be used for authenticating.</p></div> </div>  <div class="property-info">  <span class="property-name">password</span> <span class="param-type">string</span>  <div class="redoc-markdown-block"><p>The password for the account that will be used for authenticating. <strong>Note: This property is not returned in responses for security.</strong></p></div> </div>  </div>  <br>*Example:* `""` | Yes |
| description | string | The description of the credential.<br>*Example:* `""` | No |
| enabled | boolean | Flag indicating whether the credential is enabled for use during the scan.<br>*Example:* `false` | No |
| hostRestriction | string | The host name or IP address that you want to restrict the credentials to.<br>*Example:* `""` | No |
| id | integer | The identifier of the credential.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The name of the credential.<br>*Example:* `""` | Yes |
| portRestriction | integer | Further restricts the credential to attempt to authenticate on a specific port. <br>*Example:* `""` | No |

#### SiteDiscoveryConnection

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the discovery connection.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the discovery connection.<br>*Example:* `""` | No |
| type | string | The type of discovery connection configured for the site. This property only applies to dynamic sites.<br>*Enum:* `"activesync-ldap"`, `"activesync-office365"`, `"activesync-powershell"`, `"aws"`, `"dhcp"`, `"sonar"`, `"vsphere"`<br>*Example:* `""` | No |

#### SiteOrganization

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| address | string | The address.<br>*Example:* `""` | No |
| city | string | The city.<br>*Example:* `""` | No |
| contact | string | The contact person name.<br>*Example:* `""` | No |
| country | string | The country.<br>*Example:* `""` | No |
| email | string | The e-mail address.<br>*Example:* `""` | No |
| jobTitle | string | The job title.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The organization name.<br>*Example:* `""` | No |
| phone | string | The phone number.<br>*Example:* `""` | No |
| state | string | The state.<br>*Example:* `""` | No |
| url | string | The organization URL.<br>*Example:* `""` | No |
| zipCode | string | The zip or region code.<br>*Example:* `""` | No |

#### SiteSharedCredential

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| enabled | boolean | Flag indicating whether the shared credential is enabled for the site's scans.<br>*Example:* `false` | No |
| id | integer | The identifier of the shared credential.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the shared credential.<br>*Example:* `""` | No |
| service | string | The type of service the credential is configured to authenticate with.<br>*Enum:* `"as400"`, `"cifs"`, `"cifshash"`, `"cvs"`, `"db2"`, `"ftp"`, `"http"`, `"ms-sql"`, `"mysql"`, `"notes"`, `"oracle"`, `"oracle-service-name"`, `"pop"`, `"postgresql"`, `"remote-exec"`, `"snmp"`, `"snmpv3"`, `"ssh"`, `"ssh-key"`, `"sybase"`, `"telnet"`, `"kerberos"`, `"hana"`, `"scan-assistant"`<br>*Example:* `""` | No |

#### SiteUpdateResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| description | string | The site's description.<br>*Example:* `""` | No |
| engineId | integer | The identifier of a scan engine.<br>*Example:* `""` | Yes |
| importance | string | The site importance.<br>*Enum:* `"very_low"`, `"low"`, `"normal"`, `"high"`, `"very_high"`<br>*Example:* `""` | Yes |
| links | [ [Link](#link) ] |  | No |
| name | string | The site name. Name must be unique.<br>*Example:* `""` | Yes |
| scanTemplateId | string | The identifier of a scan template.<br>*Example:* `""` | Yes |

#### SmtpAlert

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| enabled | boolean | Flag indicating the alert is enabled.<br>*Example:* `false` | Yes |
| enabledScanEvents | [ScanEvents](#scanevents) | Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.<br>*Example:* `""` | No |
| enabledVulnerabilityEvents | [VulnerabilityEvents](#vulnerabilityevents) | Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.<br>*Example:* `""` | No |
| id | integer | The identifier of the alert.<br>*Example:* `""` | No |
| limitAlertText | boolean | Reports basic information in the alert, if enabled.<br>*Example:* `false` | No |
| links | [ [Link](#link) ] |  | No |
| maximumAlerts | integer | The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.<br>*Example:* `""` | No |
| name | string | The name of the alert.<br>*Example:* `""` | Yes |
| notification | string | The type of alert.<br>*Enum:* `"SMTP"`, `"SNMP"`, `"Syslog"`<br>*Example:* `""` | Yes |
| recipients | [ string ] | The recipient list. At least one recipient must be specified. Each recipient must be a valid e-mail address. | Yes |
| relayServer | string | The SMTP server/relay to send messages through.<br>*Example:* `""` | Yes |
| senderEmailAddress | string | The sender e-mail address that will appear in the from field.<br>*Example:* `""` | No |

#### SmtpSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| distributionId | string |  | No |
| host | string | The host to send to.<br>*Example:* `"mail@acme.com"` | No |
| port | integer | The port to send to.<br>*Example:* `25` | No |
| sender | string | The sender to send from.<br>*Example:* `"security@acme.com"` | No |

#### SnmpAlert

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| community | string | The SNMP community name.<br>*Example:* `""` | Yes |
| enabled | boolean | Flag indicating the alert is enabled.<br>*Example:* `false` | Yes |
| enabledScanEvents | [ScanEvents](#scanevents) | Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.<br>*Example:* `""` | No |
| enabledVulnerabilityEvents | [VulnerabilityEvents](#vulnerabilityevents) | Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.<br>*Example:* `""` | No |
| id | integer | The identifier of the alert.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| maximumAlerts | integer | The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.<br>*Example:* `""` | No |
| name | string | The name of the alert.<br>*Example:* `""` | Yes |
| notification | string | The type of alert.<br>*Enum:* `"SMTP"`, `"SNMP"`, `"Syslog"`<br>*Example:* `""` | Yes |
| server | string | The SNMP management server.<br>*Example:* `""` | Yes |

#### Software

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| configurations | [ [Configuration](#configuration) ] | The attributes of the software. | No |
| cpe | [SoftwareCpe](#softwarecpe) | The Common Platform Enumeration (CPE) of the software.<br>*Example:* `""` | No |
| description | string | The description of the software.<br>*Example:* `"Microsoft Outlook 2013 15.0.4867.1000"` | No |
| family | string | The family of the software.<br>*Example:* `"Office 2013"` | No |
| id | long |  | No |
| product | string | The product of the software.<br>*Example:* `"Outlook 2013"` | No |
| type | string | The version of the software.<br>*Example:* `"Productivity"` | No |
| vendor | string | The vendor of the software.<br>*Example:* `"Microsoft"` | No |
| version | string | The version of the software.<br>*Example:* `"15.0.4867.1000"` | No |

#### SoftwareCpe

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| edition | string | Edition-related terms applied by the vendor to the product. <br>*Example:* `"enterprise"` | No |
| language | string | Defines the language supported in the user interface of the product being described. The format is of the language tag adheres to <a target="_blank" rel="noopener noreferrer" href="https://tools.ietf.org/html/rfc5646">RFC5646</a>.<br>*Example:* `""` | No |
| other | string | Captures any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value. <br>*Example:* `""` | No |
| part | string | A single letter code that designates the particular platform part that is being identified.<br>*Enum:* `"o"`, `"a"`, `"h"`<br>*Example:* `"o"` | Yes |
| product | string | the most common and recognizable title or name of the product.<br>*Example:* `"windows_server_2008"` | No |
| swEdition | string | Characterizes how the product is tailored to a particular market or class of end users. <br>*Example:* `""` | No |
| targetHW | string | Characterize the instruction set architecture on which the product operates. <br>*Example:* `""` | No |
| targetSW | string | Characterize the software computing environment within which the product operates.<br>*Example:* `""` | No |
| update | string | Vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.<br>*Example:* `"sp1"` | No |
| v2.2 | string | The full CPE string in the <a target="_blank" rel="noopener noreferrer" href="https://cpe.mitre.org/files/cpe-specification_2.2.pdf">CPE 2.2</a> format.<br>*Example:* `"cpe:/o:microsoft:windows_server_2008:-:sp1:enterprise"` | No |
| v2.3 | string | The full CPE string in the <a target="_blank" rel="noopener noreferrer" href="http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf">CPE 2.3</a> format.<br>*Example:* `"cpe:2.3:o:microsoft:windows_server_2008:-:sp1:enterprise:*:*:*:*:*"` | No |
| vendor | string | The person or organization that manufactured or created the product.<br>*Example:* `"microsoft"` | No |
| version | string | Vendor-specific alphanumeric strings characterizing the particular release version of the product.<br>*Example:* `"-"` | No |

#### Solution

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| additionalInformation | [AdditionalInformation](#additionalinformation) | Additional information or resources that can assist in applying the remediation.<br>*Example:* `""` | No |
| appliesTo | string | The systems or software the solution applies to.<br>*Example:* `"libexpat1 on Ubuntu Linux"` | No |
| estimate | string | The estimated duration to apply the solution, in ISO 8601 format. For example: `"PT5M"`.<br>*Example:* `"PT10M"` | No |
| id | string | The identifier of the solution.<br>*Example:* `"ubuntu-upgrade-libexpat1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| steps | [Steps](#steps) | The steps required to remediate the vulnerability.<br>*Example:* `""` | No |
| summary | [Summary](#summary) | The summary of the solution.<br>*Example:* `""` | No |
| type | string | The type of the solution. One of: `"Configuration"`, `"Rollup patch"`, `"Patch"`<br>*Enum:* `"configuration"`, `"rollup-patch"`, `"patch"`, `"unknown"`<br>*Example:* `"configuration"` | No |

#### SolutionMatch

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| check | string | The identifier of the vulnerability check used to match the solution, if type is `check`.<br>*Example:* `""` | No |
| confidence | string | The confidence of the matching process for the solution.<br>*Enum:* `"exact"`, `"partial"`, `"none"`<br>*Example:* `""` | No |
| fingerprint | [Fingerprint](#fingerprint) | The fingerprint used to perform solution matching, if type is `operating-system`, `service`, or `software`.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| solution | string | The identifier of the matched solution.<br>*Example:* `"ubuntu-upgrade-libexpat1"` | No |
| type | string | The means by which a solution was matched.<br>*Enum:* `"none"`, `"check"`, `"operating-system"`, `"service"`, `"software"`<br>*Example:* `"software"` | No |

#### SonarCriteria

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| filters | [ [SonarCriterion](#sonarcriterion) ] | The filters in the Sonar query. | No |

#### SonarCriterion

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| days | integer | If the field is `scan-date-within-the-last`, the number of days to search against.<br>*Example:* `""` | No |
| domain | string | If the field is `domain-contains`, the domain to search against.<br>*Example:* `"acme.com"` | No |
| lower | string | If the field is `ip-address-range`, the lower limit of the search.<br>*Example:* `""` | No |
| type | string | The type of query to perform.<br>*Enum:* `"domain-contains"`, `"scan-date-within-the-last"`, `"ip-address-range"`<br>*Example:* `"domain-contains"` | No |
| upper | string | If the field is `ip-address-range`, the upper limit of the search.<br>*Example:* `""` | No |

#### SonarQuery

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| criteria | [SonarCriteria](#sonarcriteria) | The search criteria used to search for assets from the Sonar API.<br>*Example:* `""` | No |
| id | long | The identifier of the Sonar query.<br>*Example:* `14` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The name of the Sonar query.<br>*Example:* `"Assets in Domain"` | No |

#### StaticSite

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| excludedAssetGroups | [ExcludedAssetGroups](#excludedassetgroups) | Assets associated with these asset groups will be excluded from the site's scan.<br>*Example:* `""` | No |
| excludedTargets | [ExcludedScanTargets](#excludedscantargets) | Addresses to be excluded from the site's scan. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.<br>*Example:* `""` | No |
| includedAssetGroups | [IncludedAssetGroups](#includedassetgroups) | Assets associated with these asset groups will be included in the site's scan.<br>*Example:* `""` | No |
| includedTargets | [IncludedScanTargets](#includedscantargets) | Addresses to be included in the site's scan. At least one address must be specified in a static site. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation.<br>*Example:* `""` | No |

#### Steps

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| html | string | Textual representation of the content.<br>*Example:* `"<p>\n    Use`apt-get upgrade`to upgrade libexpat1 to the latest version.\n  </p>"` | No |
| text | string | Textual representation of the content.<br>*Example:* `"Use`apt-get upgrade`to upgrade libexpat1 to the latest version."` | No |

#### Submission

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| comment | string | A comment from the submitter as to why the exception was submitted.<br>*Example:* `""` | No |
| date | string | The date and time the vulnerability exception was submitted.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The login name of the user that submitted the vulnerability exception.<br>*Example:* `""` | No |
| reason | string | The reason the vulnerability exception was submitted. One of: `"False Positive"`, `"Compensating Control"`, `"Acceptable Use"`, `"Acceptable Risk"`, `"Other"`<br>*Example:* `""` | No |
| user | integer | The identifier of the user that submitted the vulnerability exception.<br>*Example:* `""` | No |

#### Summary

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| html | string | Textual representation of the content.<br>*Example:* `"Upgrade libexpat1"` | No |
| text | string | Textual representation of the content.<br>*Example:* `"Upgrade libexpat1"` | No |

#### SwaggerDiscoverySearchCriteriaFilter

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| field | string | The filter field for the search criteria.<br>*Example:* `""` | No |
| lower | object | The lower value to match in a range criteria.<br>*Example:* `""` | No |
| operator | string | The operator on how to match the search criteria.<br>*Example:* `""` | No |
| upper | object | The upper value to match in a range criteria.<br>*Example:* `""` | No |
| value | object | The single value to match using the operator.<br>*Example:* `""` | No |
| values | [ object ] | An array of values to match using the operator. | No |

#### SwaggerSearchCriteriaFilter

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| field | string | The filter field for the search criteria.<br>*Example:* `""` | No |
| lower | object | The lower value to match in a range criteria.<br>*Example:* `""` | No |
| operator | string | The operator on how to match the search criteria.<br>*Example:* `""` | No |
| upper | object | The upper value to match in a range criteria.<br>*Example:* `""` | No |
| value | object | The single value to match using the operator.<br>*Example:* `""` | No |
| values | [ object ] | An array of values to match using the operator. | No |

#### SyslogAlert

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| enabled | boolean | Flag indicating the alert is enabled.<br>*Example:* `false` | Yes |
| enabledScanEvents | [ScanEvents](#scanevents) | Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.<br>*Example:* `""` | No |
| enabledVulnerabilityEvents | [VulnerabilityEvents](#vulnerabilityevents) | Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.<br>*Example:* `""` | No |
| id | integer | The identifier of the alert.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| maximumAlerts | integer | The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.<br>*Example:* `""` | No |
| name | string | The name of the alert.<br>*Example:* `""` | Yes |
| notification | string | The type of alert.<br>*Enum:* `"SMTP"`, `"SNMP"`, `"Syslog"`<br>*Example:* `""` | Yes |
| server | string | The Syslog server to send messages to.<br>*Example:* `""` | Yes |

#### Tag

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| color | string | The color to use when rendering the tag in a user interface.<br>*Example:* `"default"` | No |
| created | string | The date and time the tag was created.<br>*Example:* `"2017-10-07T23:50:01.205Z"` | No |
| id | integer | The identifier of the tag.<br>*Example:* `6` | No |
| links | [ [Link](#link) ] |  | No |
| name | string | The name (label) of the tab.<br>*Example:* `"My Custom Tag"` | Yes |
| riskModifier | double | The amount to adjust risk of an asset tagged with this tag. <br>*Example:* `2` | No |
| searchCriteria | [SearchCriteria](#searchcriteria) |  | No |
| source | string | The source of the tag.<br>*Enum:* `"built-in"`, `"custom"`<br>*Example:* `"custom"` | No |
| type | string | The type of the tag.<br>*Example:* `"custom"` | Yes |

#### TagAssetSource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | If the `source` is `"asset-group"` or `"site"` the identifier of the asset group or site that causes the tag to apply to the asset.<br>*Example:* `92` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| source | string | The source by which a tag applies to an asset.<br>*Enum:* `"site"`, `"asset-group"`, `"criteria"`, `"tag"`, `"unknown"`<br>*Example:* `"site"` | No |

#### TagLink

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the tagged asset.<br>*Example:* `78` | No |
| sources | [ string ] | The source(s) by which a tag is-applied to an asset. | No |

#### TaggedAssetReferences

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| resources | [ [TagLink](#taglink) ] | The identifiers of the associated resources. | No |

#### Telnet

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| characterSet | string | The character set to use.<br>*Example:* `"ASCII"` | No |
| failedLoginRegex | string | Regular expression to match a failed login response.<br>*Example:* `"(?:[i,I]ncorrect|[u,U]nknown|[f,F]ail|[i,I]nvalid|[l,L]ogin|[p,P]assword|[p,P]asswd|[u,U]sername|[u,U]nable|[e,E]rror|[d,D]enied|[r,R]eject|[r,R]efuse|[c,C]lose|[c,C]losing|Not on system console|% Bad)"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| loginRegex | string | Regular expression to match a login response.<br>*Example:* `"(?:[l,L]ogin|[u,U]ser.?[nN]ame) *\\:"` | No |
| passwordPromptRegex | string | Regular expression to match a password prompt.<br>*Example:* `"(?:[p,P]assword|[p,P]asswd) *\\:"` | No |
| questionableLoginRegex | string | Regular expression to match a potential false negative login response.<br>*Example:* `"(?:[l,L]ast [l,L]ogin *\\:|allows only .* Telnet Client License)"` | No |

#### TokenResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| key | string | The two-factor authentication token seed (key).<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### UnauthorizedError

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| message | string | The messages indicating the cause or reason for failure.<br>*Example:* `"An error has occurred."` | No |
| status | string | The HTTP status code for the error (same as in the HTTP response).<br>*Enum:* `"401"`<br>*Example:* `"401"` | Yes |

#### UniqueId

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | string | The unique identifier.<br>*Example:* `"c56b2c59-4e9b-4b89-85e2-13f8146eb071"` | Yes |
| source | string | The source of the unique identifier.<br>*Example:* `"WQL"` | No |

#### UpdateId

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| productId | string | Product update identifier.<br>*Example:* `"281474976711146"` | No |
| versionId | string | Version update identifier.<br>*Example:* `"490"` | No |

#### UpdateInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| content | string | The most recent content update.<br>*Example:* `"3192129162"` | No |
| contentPartial | string | The most recent, partially-applied (in-memory), content update.<br>*Example:* `"723680177"` | No |
| id | [UpdateId](#updateid) | Details of update identifiers.<br>*Example:* `""` | No |
| product | string | The most recent product update.<br>*Example:* `"2200922472"` | No |

#### UpdateSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| contentAutoUpdate | boolean | Whether automatic content updates are enabled.<br>*Example:* `true` | No |
| enabled | boolean | Whether updates are enabled.<br>*Example:* `true` | No |
| productAutoUpdate | boolean | Whether automatic product updates are enabled.<br>*Example:* `true` | No |

#### User

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| authentication | [AuthenticationSource](#authenticationsource) | The authentication source used to authenticate the user.<br>*Example:* `""` | No |
| email | string | The email address of the user.<br>*Example:* `""` | No |
| enabled | boolean | Whether the user account is enabled.<br>*Example:* `false` | No |
| id | integer | The identifier of the user.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| locale | [LocalePreferences](#localepreferences) | The locale and language preferences for the user.<br>*Example:* `""` | No |
| locked | boolean | Whether the user account is locked (exceeded maximum password retry attempts).<br>*Example:* `false` | No |
| login | string | The login name of the user.<br>*Example:* `""` | Yes |
| name | string | The full name of the user.<br>*Example:* `""` | Yes |
| role | [UserRole](#userrole) | The privileges and role the user is assigned.<br>*Example:* `""` | No |

#### UserAccount

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| fullName | string | The full name of the user account.<br>*Example:* `"Smith, John"` | No |
| id | integer | The identifier of the user account.<br>*Example:* `8952` | No |
| name | string | The name of the user account.<br>*Example:* `"john_smith"` | No |

#### UserCreateRole

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| allAssetGroups | boolean | Whether to grant the user access to all asset groups. Defaults to `false`.<br>*Example:* `false` | No |
| allSites | boolean | Whether to grant the user access to all sites. Defaults to `false`.<br>*Example:* `false` | No |
| id | string | The identifier of the role the user is assigned to.<br>*Example:* `""` | Yes |
| superuser | boolean | Whether the user is a superuser. Defaults to `false`.<br>*Example:* `false` | No |

#### UserEdit

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| authentication | [CreateAuthenticationSource](#createauthenticationsource) | The details of the authentication source used to authenticate the user.<br>*Example:* `""` | No |
| email | string | The email address of the user.<br>*Example:* `""` | No |
| enabled | boolean | Whether the user account is enabled. Defaults to `true`.<br>*Example:* `false` | No |
| id | integer | The identifier of the user.<br>*Example:* `""` | No |
| locale | [LocalePreferences](#localepreferences) | The locale and language preferences for the user.<br>*Example:* `""` | No |
| locked | boolean | Whether the user account is locked (exceeded maximum password retry attempts).<br>*Example:* `false` | No |
| login | string | The login name of the user.<br>*Example:* `""` | Yes |
| name | string | The full name of the user.<br>*Example:* `""` | Yes |
| password | string | The password to use for the user.<br>*Example:* `""` | Yes |
| passwordResetOnLogin | boolean | Whether to require a reset of the user's password upon first login. Defaults to `false`.<br>*Example:* `false` | No |
| role | [UserCreateRole](#usercreaterole) | The privileges and role to assign the user.<br>*Example:* `""` | Yes |

#### UserRole

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| allAssetGroups | boolean | Whether the user has access to all asset groups.<br>*Example:* `false` | No |
| allSites | boolean | Whether the user has access to all sites.<br>*Example:* `false` | No |
| id | string | The identifier of the role the user is assigned to.<br>*Example:* `""` | No |
| name | string | The name of the role the user is assigned to.<br>*Example:* `""` | No |
| privileges | [ string ] | The privileges granted to the user by their role. | No |
| superuser | boolean | Whether the user is a superuser.<br>*Example:* `false` | No |

#### VersionInfo

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| build | string | The build number.<br>*Example:* `"2017-12-10-14-11"` | No |
| changeset | string | The changeset of the source build.<br>*Example:* `"7061fb4e7c355160df79a77d8983bed2af01f2bf"` | No |
| platform | string | The platform of the build.<br>*Example:* `"Linux64"` | No |
| semantic | string | The semantic version number of the installation.<br>*Example:* `"6.4.65"` | No |
| update | [UpdateInfo](#updateinfo) | Version update details.<br>*Example:* `""` | No |

#### Vulnerabilities

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| critical | long | The number of critical vulnerabilities.<br>*Example:* `16` | No |
| moderate | long | The number of moderate vulnerabilities.<br>*Example:* `3` | No |
| severe | long | The number of severe vulnerabilities.<br>*Example:* `76` | No |
| total | long | The total number of vulnerabilities.<br>*Example:* `95` | No |

#### Vulnerability

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| added | string | The date the vulnerability coverage was added. The format is an ISO 8601 date, `YYYY-MM-DD`.<br>*Example:* `"2017-10-10"` | No |
| categories | [ string ] | All vulnerability categories assigned to this vulnerability. | No |
| cves | [ string ] | All <a target="_blank" rel="noopener noreferrer" href="https://cve.mitre.org/">CVE</a>s assigned to this vulnerability. | No |
| cvss | [VulnerabilityCvss](#vulnerabilitycvss) | The CVSS vector(s) for the vulnerability.<br>*Example:* `""` | No |
| denialOfService | boolean | Whether the vulnerability can lead to Denial of Service (DoS).<br>*Example:* `false` | No |
| description | [ContentDescription](#contentdescription) | The description of the vulnerability.<br>*Example:* `""` | No |
| exploits | integer | The exploits that can be used to exploit a vulnerability.<br>*Example:* `""` | No |
| id | string | The identifier of the vulnerability.<br>*Example:* `"msft-cve-2017-11804"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| malwareKits | integer | The malware kits that are known to be used to exploit the vulnerability.<br>*Example:* `""` | No |
| modified | string | The last date the vulnerability was modified. The format is an ISO 8601 date, `YYYY-MM-DD`.<br>*Example:* `"2017-10-10"` | No |
| pci | [PCI](#pci) | Details the <a target="_blank" rel="noopener noreferrer" href="https://www.pcisecuritystandards.org/">Payment Card Industry (PCI)</a> details of the vulnerability.<br>*Example:* `""` | No |
| published | string | The date the vulnerability was first published or announced. The format is an ISO 8601 date, `YYYY-MM-DD`.<br>*Example:* `"2017-10-10"` | No |
| riskScore | double | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000.<br>*Example:* `123.69` | No |
| severity | string | The severity of the vulnerability, one of: `"Moderate"`, `"Severe"`, `"Critical"`.<br>*Example:* `"Severe"` | No |
| severityScore | integer | The severity score of the vulnerability, on a scale of 0-10.<br>*Example:* `4` | No |
| title | string | The title (summary) of the vulnerability.<br>*Example:* `"Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability"` | No |

#### VulnerabilityCategory

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | integer | The identifier of the vulnerability category.<br>*Example:* `23` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| name | string | The name of the category.<br>*Example:* `"Microsoft"` | No |

#### VulnerabilityCheck

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | string | The identifier of the vulnerability check.<br>*Example:* `"WINDOWS-HOTFIX-MS14-009-01123281-bac0-44d8-a729-cd31c19d6bd1"` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| plugin | string | The name of the plugin (module) the check belongs to.<br>*Example:* `"WindowsHotfixScanner"` | No |
| potential | boolean | Whether the check results in potential vulnerabilities.<br>*Example:* `false` | No |
| requiresCredentials | boolean | Whether the check requires credentials in order to run.<br>*Example:* `true` | No |
| safe | boolean | Whether the checked is deemed to be "safe" to run. A safe check is one that can be run without negatively impacting the host it is run against.<br>*Example:* `true` | No |
| service | boolean | Whether the check operates against a service, or false it it is a local check.<br>*Example:* `false` | No |
| unique | boolean | Whether the check may only register a result once during a scan of host. Otherwise, the tests in the check can run multiple times, possibly registering multiple results.<br>*Example:* `false` | No |
| vulnerability | string | The identifier of the vulnerability the check results in.<br>*Example:* `"windows-hotfix-ms14-009"` | No |

#### VulnerabilityCheckType

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| disabled | [ string ] | The types of vulnerability checks to disable during a scan. | No |
| enabled | [ string ] | The types of vulnerability checks to enable during a scan. | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |

#### VulnerabilityCvss

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| v2 | [VulnerabilityCvssV2](#vulnerabilitycvssv2) | The Common Vulnerability Scoring System (<a href="https://www.first.org/cvss/v2/guide">CVSS v2</a>) information for the vulnerability.<br>*Example:* `""` | No |
| v3 | [VulnerabilityCvssV3](#vulnerabilitycvssv3) | The Common Vulnerability Scoring System (<a target="_blank" rel="noopener noreferrer" href="https://www.first.org/cvss/specification-document">CVSS v3</a>) information for the vulnerability.<br>*Example:* `""` | No |

#### VulnerabilityCvssV2

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| accessComplexity | string | Access Complexity (AC) component which measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system.  \| Access Complexity       \| Description                                                              \|  \| ----------------------- \| ------------------------------------------------------------------------ \|  \| High (`"H"`)            \| Specialized access conditions exist.                                     \|  \| Medium (`"M"`)          \| The access conditions are somewhat specialized.                          \|  \| Low (`"L"`)             \| Specialized access conditions or extenuating circumstances do not exist. \|<br>*Enum:* `"L"`, `"M"`, `"H"`<br>*Example:* `"M"` | No |
| accessVector | string | Access Vector (Av) component which reflects how the vulnerability is exploited.  \| Access Vector              \| Description \|  \| -------------------------- \| ----------- \|  \| Local (`"L"`)              \| A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. \|  \| Adjacent Network (`"A"`)   \| A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software. \|  \| Network (`"N"`)            \| A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". \|  <br>*Enum:* `"L"`, `"A"`, `"N"`<br>*Example:* `"L"` | No |
| authentication | string | Authentication (Au) component which measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability.  \| Authentication       \| Description \|  \| -------------------- \| ----------- \|  \| Multiple (`"M"`)     \| Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. \|  \| Single (`"S"`)       \| The vulnerability requires an attacker to be logged into the system.                                                                     \|  \| None (`"N"`)         \| Authentication is not required to exploit the vulnerability.                                                                             \|<br>*Enum:* `"N"`, `"S"`, `"M"`<br>*Example:* `"N"` | No |
| availabilityImpact | string | Availability Impact (A) component which measures the impact to availability of a successfully exploited vulnerability.  \| Availability Impact        \| Description  \|  \| -------------------------- \| ------------ \|  \| None (`"N"`)               \| There is no impact to the availability of the system. \|  \| Partial (`"P"`)            \| There is reduced performance or interruptions in resource availability. \|  \| Complete (`"C"`)           \| There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable. \|<br>*Enum:* `"N"`, `"P"`, `"C"`<br>*Example:* `"P"` | No |
| confidentialityImpact | string | Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability.  \| Confidentiality Impact     \| Description  \|  \| -------------------------- \| ------------ \|  \| None (`"N"`)               \| There is no impact to the confidentiality of the system. \|  \| Partial (`"P"`)            \| There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. \|  \| Complete (`"C"`)           \| There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system's data (memory, files, etc.) \| <br>*Enum:* `"N"`, `"P"`, `"C"`<br>*Example:* `"P"` | No |
| exploitScore | double | The CVSS exploit score.<br>*Example:* `3.3926` | No |
| impactScore | double | The CVSS impact score.<br>*Example:* `6.443` | No |
| integrityImpact | string | Integrity Impact (I) component measures the impact to integrity of a successfully exploited vulnerability.  \| Integrity Impact           \| Description  \|  \| -------------------------- \| ------------ \|  \| None (`"N"`)               \| There is no impact to the integrity of the system. \|  \| Partial (`"P"`)            \| Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. \|  \| Complete (`"C"`)           \| There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system. \|<br>*Enum:* `"N"`, `"P"`, `"C"`<br>*Example:* `"P"` | No |
| score | double | The CVSS score, which ranges from 0-10.<br>*Example:* `4.4` | No |
| vector | string | The <a target="_blank" rel="noopener noreferrer" href="https://www.first.org/cvss/v2/guide">CVSS v2</a> vector.<br>*Example:* `"AV:L/AC:M/Au:N/C:P/I:P/A:P"` | No |

#### VulnerabilityCvssV3

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| attackComplexity | string | Access Complexity (AC) component with measures the conditions beyond the attacker's control that must exist in order to exploit the vulnerability.  \| Access Complexity      \| Description                                                              \|  \| ---------------------- \| ------------------------------------------------------------------------ \|  \| Low (`"L"`)            \| Specialized access conditions or extenuating circumstances do not exist. \|  \| High (`"H"`)           \| A successful attack depends on conditions beyond the attacker's control. \|<br>*Enum:* `"L"`, `"H"`<br>*Example:* `"H"` | No |
| attackVector | string | Attack Vector (AV) component which measures context by which vulnerability exploitation is possible.  \| Access Vector          \| Description                                                              \|  \| ---------------------- \| ------------------------------------------------------------------------ \|  \| Local (`"L"`)          \| A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. \|  \| Adjacent (`"A"`)       \| A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software. \|  \| Network (`"N"`)        \| A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". \|  <br>*Enum:* `"N"`, `"A"`, `"L"`, `"P"`<br>*Example:* `"N"` | No |
| availabilityImpact | string | Availability Impact (A) measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability.  \| Availability Impact        \| Description  \|  \| -------------------------- \| ------------ \|  \| High (`"H"`)               \| There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). \|  \| Low (`"L"`)                \| There is reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. \|  \| None (`"N"`)               \| There is no impact to availability within the impacted component. \|<br>*Enum:* `"N"`, `"L"`, `"H"`<br>*Example:* `"H"` | No |
| confidentialityImpact | string | Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability.  \| Confidentiality Impact     \| Description  \|  \| -------------------------- \| ------------ \|  \| High (`"H"`)               \| There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. \|  \| Low (`"L"`)                \| There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. \|  \| None (`"N"`)               \| There is no loss of confidentiality within the impacted component. \|<br>*Enum:* `"N"`, `"L"`, `"H"`<br>*Example:* `"H"` | No |
| exploitScore | double | The CVSS impact score.<br>*Example:* `1.6201` | No |
| impactScore | double | The CVSS exploit score.<br>*Example:* `5.8731` | No |
| integrityImpact | string | Integrity Impact (I) measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.  \| Integrity Impact    \| Description  \|  \| ------------------- \| ------------ \|  \| High (`"H"`)        \| There is a total loss of integrity, or a complete loss of protection. \|  \| Low (`"L"`)         \| Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is constrained. \|  \| None (`"N"`)        \| There is no loss of integrity within the impacted component. \|<br>*Enum:* `"N"`, `"L"`, `"H"`<br>*Example:* `"H"` | No |
| privilegeRequired | string | Privileges Required (PR) measures the level of privileges an attacker must possess before successfully exploiting the vulnerability.  \| Privileges Required (PR)     \| Description                                                              \|  \| ---------------------------- \| ------------------------------------------------------------------------ \|  \| None (`"N"`)                 \| The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack. \|  \| Low (`"L"`)                  \| The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. \|  \| High (`"H"`)                 \| The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files. \|<br>*Enum:* `"N"`, `"L"`, `"H"`<br>*Example:* `"N"` | No |
| scope | string | Scope (S) measures the collection of privileges defined by a computing authority (e.g. an application, an operating system, or a sandbox environment) when granting access to computing resources (e.g. files, CPU, memory, etc). These privileges are assigned based on some method of identification and authorization.  \| Scope (S)            \| Description                                                              \|  \| -------------------- \| ------------------------------------------------------------------------ \|  \| Unchanged (`"U"`)    \| An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same. \|  \| Changed (`"C"`)      \| An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different. \|<br>*Enum:* `"U"`, `"C"`<br>*Example:* `"U"` | No |
| score | double | The CVSS score, which ranges from 0-10.<br>*Example:* `7.5` | No |
| userInteraction | string | User Interaction (UI) measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component.  \| User Interaction (UI)        \| Description                                                               \|  \| ---------------------------- \| ------------------------------------------------------------------------- \|  \| None (`"N"`)                 \| The vulnerable system can be exploited without interaction from any user. \|  \| Required (`"R"`)             \| Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. \|<br>*Enum:* `"N"`, `"R"`<br>*Example:* `"R"` | No |
| vector | string | The <a target="_blank" rel="noopener noreferrer" href="https://www.first.org/cvss/specification-document">CVSS v3</a> vector.<br>*Example:* `"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"` | No |

#### VulnerabilityEvents

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| confirmedVulnerabilities | boolean | Generates an alert for vulnerability results of confirmed vulnerabilties. A vulnerability is "confirmed" when asset-specific vulnerability tests, such as exploits, produce positive results. Default value is `true`.<br>*Example:* `false` | Yes |
| potentialVulnerabilities | boolean | Generates an alert for vulnerability results of potential vulnerabilties. A vulnerability is "potential" if a check for a potential vulnerabilty is positive. Default value is `true`.<br>*Example:* `false` | Yes |
| unconfirmedVulnerabilities | boolean | Generates an alert for vulnerability results of unconfirmed vulnerabilties. A vulnerability is "unconfirmed" when a version of a scanned service or software is known to be vulnerable, but there is no positive verification. Default value is `true`.<br>*Example:* `false` | Yes |
| vulnerabilitySeverity | string | Generates an alert for vulnerability results of the selected vulnerability severity. Default value is `"any_severity"`.<br>*Enum:* `"any_severity"`, `"severe_and_critical"`, `"only_critical"`<br>*Example:* `""` | Yes |

#### VulnerabilityException

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| expires | string | The date and time the vulnerability exception is set to expire.<br>*Example:* `""` | No |
| id | integer | The identifier of the vulnerability exception.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] |  | No |
| review | [Review](#review) | Details regarding the review and/or approval of the exception.<br>*Example:* `""` | No |
| scope | [ExceptionScope](#exceptionscope) | The scope of the vulnerability exception, indicating the results it applies to.<br>*Example:* `""` | No |
| state | string | The state of the vulnerability exception. One of: `"Deleted"`, `"Expired"`, `"Approved"`, `"Rejected"`, `"Under Review".<br>*Example:*`""` | No |
| submit | [Submission](#submission) | Details regarding the submission of the exception.<br>*Example:* `""` | No |

#### VulnerabilityFinding

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | string | The identifier of the vulnerability.<br>*Example:* `"ssh-openssh-x11uselocalhost-x11-forwarding-session-hijack"` | Yes |
| instances | integer | The number of vulnerable occurrences of the vulnerability. This does not include `invulnerable` instances.<br>*Example:* `1` | Yes |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| results | [ [AssessmentResult](#assessmentresult) ] | The vulnerability check results for the finding. Multiple instances may be present if one or more checks fired, or a check has multiple independent results. | No |
| since | string | The date and time the finding was was first recorded, in the ISO8601 format. If the result changes status this value is the date and time of the status change.<br>*Example:* `"2017-08-09T11:32:33.658Z"` | No |
| status | string | The status of the finding.<br>*Enum:* `"vulnerable"`, `"invulnerable"`, `"no-results"`<br>*Example:* `"vulnerable"` | Yes |

#### VulnerabilityReference

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| advisory | [AdvisoryLink](#advisorylink) | Hypermedia link to the destination of the vulnerability reference.<br>*Example:* `""` | No |
| id | integer | The identifier of the vulnerability reference.<br>*Example:* `157986` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| reference | string | The contents of the reference, typically an identifier or hyperlink. Example: `"CVE-2011-0762"`<br>*Example:* `"4041689"` | No |
| source | string | The originating source of the reference. Examples: `"url"`, `"cve"`, `"bid"`, `"redhat"`<br>*Example:* `"mskb"` | No |

#### VulnerabilityValidationResource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| date | string | The date and time the vulnerability was validated, in the ISO8601 format.<br>*Example:* `"2017-12-21T04:54:32.314Z"` | No |
| id | long | The identifier of the vulnerability validation.<br>*Example:* `46` | No |
| links | [ [Link](#link) ] |  | No |
| source | [VulnerabilityValidationSource](#vulnerabilityvalidationsource) | The source used to validate the vulnerability.<br>*Example:* `""` | No |

#### VulnerabilityValidationSource

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| key | string | The identifier or name of the exploit that was used to validate the vulnerability.<br>*Example:* `"exploit/windows/iis/iis_webdav_scstoragepathfromurl"` | No |
| name | string | The name of the source used to validate the vulnerability.<br>*Enum:* `"metasploit"`, `"other"`<br>*Example:* `"metasploit"` | No |

#### WebApplication

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| id | long | The identifier of the web application.<br>*Example:* `30712` | No |
| pages | [ [WebPage](#webpage) ] | The pages discovered on the web application. | No |
| root | string | The web root of the web application.<br>*Example:* `"/"` | No |
| virtualHost | string | The virtual host of the web application.<br>*Example:* `"102.89.22.253"` | No |

#### WebFormAuthentication

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| baseURL | string | The base URL is the main address from which all paths in the target Web site begin. Includes the protocol. Example: http://acme.com.<br>*Example:* `""` | No |
| enabled | boolean | Flag indicating whether the HTML form web authentication is enabled for the site's scans.<br>*Example:* `false` | No |
| id | integer | The identifier of the HTML form web authentication.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| loginRegularExpression | string | The regular expression matches the message that the Web server returns if the login attempt fails.<br>*Example:* `""` | No |
| loginURL | string | The login page URL contains form for logging on. Include the base URL. Example: http://acme.com/login.<br>*Example:* `""` | No |
| name | string | The HTML form web authentication name.<br>*Example:* `""` | No |
| service | string | Value indicating whether this web authentication  configuration is for HTML form authentication or HTTP header authentication.<br>*Enum:* `"html-form"`, `"http-header"`<br>*Example:* `""` | No |

#### WebHeaderAuthentication

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| baseURL | string | The base URL is the main address from which all paths in the target Web site begin. Includes the protocol. Example: http://acme.com.<br>*Example:* `""` | No |
| enabled | boolean | Flag indicating whether the HTTP header web authentication is enabled for the site's scans.<br>*Example:* `false` | No |
| headers | object | A map of HTTP headers the scan engine will use when negotiating with the Web server for an "authenticated" page. Make sure that the session ID is valid between the time you save this ID for the site and when you start the scan. Note: This property is not returned in responses for security.<br>*Example:* `""` | No |
| id | integer | The identifier of the HTTP header web authentication.<br>*Example:* `""` | No |
| links | [ [Link](#link) ] | Hypermedia links to corresponding or related resources. | No |
| loginRegularExpression | string | The regular expression matches the message that the Web server returns if the login attempt fails.<br>*Example:* `""` | No |
| name | string | The HTTP header web authentication name.<br>*Example:* `""` | No |
| service | string | Value indicating whether this web authentication  configuration is for HTML form authentication or HTTP header authentication.<br>*Enum:* `"html-form"`, `"http-header"`<br>*Example:* `""` | No |

#### WebPage

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| linkType | string | The type of link used to traverse or detect the page.<br>*Enum:* `"seed"`, `"html-ref"`, `"robots"`, `"js-string"`, `"query-param"`, `"pdf"`, `"css"`, `"implied-dir"`, `"rss"`, `"redirection"`, `"sitemap"`, `"backup"`, `"vck-rewrite"`, `"non-ref-guess"`, `"soft-404"`<br>*Example:* `"html-ref"` | No |
| path | string | The path to the page (URI).<br>*Example:* `"/docs/config/index.html"` | No |
| response | integer | The HTTP response code observed with retrieving the page.<br>*Example:* `200` | No |

#### WebSettings

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| maxThreads | integer | The maximum number of request handling threads.<br>*Example:* `100` | No |
| minThreads | integer | The minimum number of request handling threads.<br>*Example:* `10` | No |
| port | integer | The port the web server is accepting requests.<br>*Example:* `3780` | No |
| sessionTimeout | string | Session timeout duration, in ISO 8601 format. For example: `"PT10M"`.<br>*Example:* `"PT10M"` | No |
