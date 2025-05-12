## Policy Override
Policy Override Resource Controller

### /api/3/assets/{id}/policy_overrides

#### GET
##### Summary

Asset Policy Overrides

##### Description

Retrieves policy overrides defined on policy rules for the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABPolicyOverride%C2%BB](#resources%c2%abpolicyoverride%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policy_overrides

#### GET
##### Summary

Policy Overrides

##### Description

Retrieves policy overrides defined on policy rules.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyOverride%C2%BB](#pageof%c2%abpolicyoverride%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Policy Overrides

##### Description

Submit a policy override. The policy override can be submitted or it can be submitted and approved in a single request.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyOverride | body | The specification of a policy override. Allows users to override the compliance result of a policy rule. | No | [PolicyOverride](#policyoverride) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABPolicyOverrideID,Link%C2%BB](#createdreference%c2%abpolicyoverrideid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policy_overrides/{id}

#### GET
##### Summary

Policy Override

##### Description

Retrieve the specified policy override.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy override. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyOverride](#policyoverride) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Policy Override

##### Description

Removes a policy override created for a policy rule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy override. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policy_overrides/{id}/expires

#### GET
##### Summary

Policy Override Expiration

##### Description

Get the expiration date for a policy override.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy override. | Yes | long |

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

Policy Override Expiration

##### Description

Set the expiration date for a policy override. This must be a valid date in the future.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy override. | Yes | long |
| expiration | body | The date the policy override is set to expire. Date is represented in ISO 8601 format. | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policy_overrides/{id}/{status}

#### POST
##### Summary

Policy Override Status

##### Description

Update the status of the specified policy override. The status can be one of the following: `"recall"`, `"approve"`, or `"reject"`.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy override. | Yes | long |
| status | path | Policy Override Status | Yes | string |
| comment | body | A comment describing the change of the policy override status. | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> |  |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Vulnerability Result
Resources and operations for retrieving vulnerability results on assessed assets.

### /api/3/assets/{id}/services/{protocol}/{port}/vulnerabilities

#### GET
##### Summary

Asset Service Vulnerabilities

##### Description

Retrieves the vulnerabilities present on a service running on an asset. A finding may be `invulnerable` if all instances on the service have exceptions applied.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityFinding%C2%BB](#pageof%c2%abvulnerabilityfinding%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/vulnerabilities

#### GET
##### Summary

Asset Vulnerabilities

##### Description

Retrieves all vulnerability findings on an asset. A finding may be `invulnerable` if all instances have exceptions applied.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityFinding%C2%BB](#pageof%c2%abvulnerabilityfinding%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/vulnerabilities/{vulnerabilityId}

#### GET
##### Summary

Asset Vulnerability

##### Description

Retrieves the details for a vulnerability finding on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityFinding](#vulnerabilityfinding) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/vulnerabilities/{vulnerabilityId}/validations

#### GET
##### Summary

Asset Vulnerability Validations

##### Description

Returns all vulnerability validations for a vulnerability on an asset. The asset must be currently vulnerable to the validated vulnerable for the validation to be returned.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABVulnerabilityValidationResource%C2%BB](#resources%c2%abvulnerabilityvalidationresource%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Asset Vulnerability Validations

##### Description

Creates a vulnerability validation for a vulnerability on an asset. The validation signifies that the vulnerability has been confirmed exploitable by an external tool, such as <a target="_blank" rel="noopener noreferrer" href="https://www.metasploit.com">Metasploit</a>.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |
| validation | body | A vulnerability validation for a vulnerability on an asset. The  validation signifies that the vulnerability has been confirmed exploitable by an external tool, such as <a target="_blank" rel="noopener noreferrer" href="https://www.metasploit.com">Metasploit</a>. | No | [VulnerabilityValidationResource](#vulnerabilityvalidationresource) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABVulnerabilityValidationID,Link%C2%BB](#createdreference%c2%abvulnerabilityvalidationid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/vulnerabilities/{vulnerabilityId}/validations/{validationId}

#### GET
##### Summary

Asset Vulnerability Validation

##### Description

Returns a vulnerability validation for a vulnerability on an asset. The asset must be currently vulnerable to the validated vulnerable for the validation to be returned.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |
| validationId | path | The identifier of the vulnerability validation. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityValidationResource](#vulnerabilityvalidationresource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Asset Vulnerability Validation

##### Description

Removes a vulnerability validation for a vulnerability from an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |
| validationId | path | The identifier of the vulnerability validation. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Remediation
Resources for determining the details required to remediate vulnerabilities.

### /api/3/assets/{id}/vulnerabilities/{vulnerabilityId}/solution

#### GET
##### Summary

Asset Vulnerability Solution

##### Description

Returns the highest-superceding rollup solutions for a vulnerability on an asset. The solution(s) selected will be the most recent and cost-effective means by which the vulnerability can be remediated.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| vulnerabilityId | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABMatchedSolution%C2%BB](#resources%c2%abmatchedsolution%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## User
Resources and operations for managing users, permissions, and privileges.

### /api/3/authentication_sources

#### GET
##### Summary

Authentication Sources

##### Description

Returns all available sources of authentication for users.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAuthenticationSource%C2%BB](#resources%c2%abauthenticationsource%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/authentication_sources/{id}

#### GET
##### Summary

Authentication Source

##### Description

Returns the details for an authentication source.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the authentication source. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [AuthenticationSource](#authenticationsource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/authentication_sources/{id}/users

#### GET
##### Summary

Authentication Source Users

##### Description

Returns hypermedia links for the user accounts that use the authentication source to authenticate.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the authentication source. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABUserID,Link%C2%BB](#referenceswith%c2%abuserid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/privileges

#### GET
##### Summary

Privileges

##### Description

Returns all privileges that may be granted to a role.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Privileges](#privileges) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/privileges/{id}

#### GET
##### Summary

Privilege

##### Description

Returns the details for a privilege.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the privilege. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/privileges/{id}/users

#### GET
##### Summary

Users With Privilege

##### Description

Returns hypermedia links for all users granted the specified privilege by their role.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the privilege. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABUserID,Link%C2%BB](#referenceswith%c2%abuserid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/roles

#### GET
##### Summary

Roles

##### Description

Returns all roles for which users may be assigned.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABRole%C2%BB](#resources%c2%abrole%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/roles/{id}

#### GET
##### Summary

Role

##### Description

Retrieves the details of a role.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the role. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Role](#role) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Role

##### Description

Updates the details of a role.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| role | body | The details of the role. | No | [Role](#role) |
| id | path | The identifier of the role. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Role

##### Description

Removes a role with the specified identifier. The role must not be built-in and cannot be currently assigned to any users.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the role. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/roles/{id}/users

#### GET
##### Summary

Users With Role

##### Description

Returns hypermedia links for the the users currently assigned a role.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the role. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABUserID,Link%C2%BB](#referenceswith%c2%abuserid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users

#### GET
##### Summary

Users

##### Description

Returns all defined users. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABUser%C2%BB](#pageof%c2%abuser%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Users

##### Description

Creates a new user. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| user | body | The details of the user. | No | [UserEdit](#useredit) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABUserID,Link%C2%BB](#createdreference%c2%abuserid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}

#### GET
##### Summary

User

##### Description

Returns the details for a user.<span class="authorization">Global Administrator, Current User</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [User](#user) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

User

##### Description

Updates the details of a user. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| user | body | The details of the user. | No | [UserEdit](#useredit) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

User

##### Description

Deletes a user account.<span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/2FA

#### GET
##### Summary

Two-Factor Authentication

##### Description

Retrieves the current authentication token seed (key) for the user, if configured.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [TokenResource](#tokenresource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Two-Factor Authentication

##### Description

Regenerates a new authentication token seed (key) and updates it for the user. This key may be then be used in the appropriate 2FA authenticator.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [TokenResource](#tokenresource) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Two-Factor Authentication

##### Description

Sets the authentication token seed (key) for the user. This key may be then be used in the appropriate 2FA authenticator.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| token | body | The authentication token seed (key) to use for the user. | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/asset_groups

#### GET
##### Summary

Asset Groups Access

##### Description

Returns the asset groups to which the user has access.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABAssetGroupID,Link%C2%BB](#referenceswith%c2%abassetgroupid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Asset Groups Access

##### Description

Updates the asset groups to which the user has access. Individual asset group access cannot be granted to users with the `allAssetGroups` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| assetGroupIds | body | The identifiers of the asset groups to grant the user access to. Ignored if user has access to `allAssetGroups`. | No | [ integer ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Asset Groups Access

##### Description

Revokes access to all asset groups from the user.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/asset_groups/{assetGroupId}

#### PUT
##### Summary

Asset Group Access

##### Description

Grants the user access to the asset group. Individual asset group access cannot be granted to users with the `allAssetGroups` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| assetGroupId | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Asset Group Access

##### Description

Grants the user access to the asset group. Individual asset group access cannot be granted to users with the `allAssetGroups` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| assetGroupId | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/lock

#### DELETE
##### Summary

Unlock Account

##### Description

Unlocks a locked user account that has too many failed authentication attempts. Disabled accounts may not be unlocked.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/password

#### PUT
##### Summary

Password Reset

##### Description

Changes the password for the user. Users may only change their own password.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| password | body | The new password to set. | No | [PasswordResource](#passwordresource) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/privileges

#### GET
##### Summary

User Privileges

##### Description

Returns the privileges granted to the user by their role. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Privileges](#privileges) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/sites

#### GET
##### Summary

Sites Access

##### Description

Returns the sites to which the user has access.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABSiteID,Link%C2%BB](#referenceswith%c2%absiteid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Sites Access

##### Description

Updates the sites to which the user has access. Individual site access cannot be granted to users with the `allSites` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| siteIds | body | The identifiers of the sites to grant the user access to. Ignored if the user has access to `allSites`. | No | [ integer ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Sites Access

##### Description

Revokes access to all sites from the user.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/users/{id}/sites/{siteId}

#### PUT
##### Summary

Site Access

##### Description

Grants the user access to the site. Individual site access cannot be granted to users with the `allSites` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| siteId | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Site Access

##### Description

Grants the user access to the site. Individual site access cannot be granted to users with the `allSites` permission. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the user. | Yes | integer |
| siteId | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Asset Discovery
Resources for managing and viewing the mechanisms used to automatically discover assets.

### /api/3/discovery_connections

#### GET
##### Summary

Discovery Connections

##### Description

Returns all discovery connections.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABDiscoveryConnection%C2%BB](#pageof%c2%abdiscoveryconnection%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/discovery_connections/{id}

#### GET
##### Summary

Discovery Connection

##### Description

Returns a discovery connection.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the discovery connection. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [DiscoveryConnection](#discoveryconnection) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/discovery_connections/{id}/connect

#### POST
##### Summary

Discovery Connection Reconnect

##### Description

Attempts to reconnect the discovery connection.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the discovery connection. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> |  |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sonar_queries

#### GET
##### Summary

Sonar Queries

##### Description

Returns all sonar queries.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSonarQuery%C2%BB](#resources%c2%absonarquery%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Sonar Queries

##### Description

Creates a sonar query.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| query | body | The criteria for a Sonar query. | No | [SonarQuery](#sonarquery) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABDiscoveryQueryID,Link%C2%BB](#createdreference%c2%abdiscoveryqueryid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sonar_queries/search

#### POST
##### Summary

Sonar Query Search

##### Description

Executes a Sonar query to discover assets with the given search criteria.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| query | body | The criteria for a Sonar query. | No | [SonarCriteria](#sonarcriteria) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ [DiscoveryAsset](#discoveryasset) ] |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sonar_queries/{id}

#### GET
##### Summary

Sonar Query

##### Description

Returns a sonar query.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the Sonar query. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SonarQuery](#sonarquery) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Sonar Query

##### Description

Updates a sonar query.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the Sonar query. | Yes | long |
| query | body | The criteria for a Sonar query. | No | [SonarQuery](#sonarquery) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Sonar Query

##### Description

Removes a sonar query.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the Sonar query. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sonar_queries/{id}/assets

#### GET
##### Summary

Sonar Query Assets

##### Description

Returns the assets that are discovered by a Sonar query.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the Sonar query. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABDiscoveryAsset%C2%BB](#resources%c2%abdiscoveryasset%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Vulnerability
Resources and operations for viewing vulnerability content and managing exceptions.

### /api/3/exploits

#### GET
##### Summary

Exploits

##### Description

Returns all known exploits.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABExploit%C2%BB](#pageof%c2%abexploit%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/exploits/{id}

#### GET
##### Summary

Exploit

##### Description

Returns the details for an exploit.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the exploit. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Exploit](#exploit) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/exploits/{id}/vulnerabilities

#### GET
##### Summary

Exploitable Vulnerabilities

##### Description

Returns the vulnerabilities exploitable to a exploit.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the exploit. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABVulnerabilityNaturalID,Link%C2%BB](#referenceswith%c2%abvulnerabilitynaturalid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/malware_kits

#### GET
##### Summary

Malware Kits

##### Description

Returns all known malware kits.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABMalwareKit%C2%BB](#pageof%c2%abmalwarekit%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/malware_kits/{id}

#### GET
##### Summary

Malware Kit

##### Description

Returns the details for a malware kit.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the malware kit. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [MalwareKit](#malwarekit) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/malware_kits/{id}/vulnerabilities

#### GET
##### Summary

Malware Kit Vulnerabilities

##### Description

Returns the vulnerabilities that are susceptible to being attacked by a malware kit.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the malware kit. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABVulnerabilityNaturalID,Link%C2%BB](#referenceswith%c2%abvulnerabilitynaturalid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/solutions

#### GET
##### Summary

Solutions

##### Description

Returns the details for all solutions.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSolution%C2%BB](#resources%c2%absolution%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/solutions/{id}

#### GET
##### Summary

Solution

##### Description

Returns the details for a solution that can remediate one or more vulnerabilities.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the solution. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Solution](#solution) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/solutions/{id}/prerequisites

#### GET
##### Summary

Solution Prerequisites

##### Description

Returns the solutions that must be executed in order for a solution to resolve a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the solution. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABSolutionNaturalID,Link%C2%BB](#referenceswith%c2%absolutionnaturalid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/solutions/{id}/supersedes

#### GET
##### Summary

Superseded Solutions

##### Description

Returns the solutions that are superseded by this solution.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the solution. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSolution%C2%BB](#resources%c2%absolution%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/solutions/{id}/superseding

#### GET
##### Summary

Superseding Solutions

##### Description

Returns the solutions that supersede this solution.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the solution. | Yes | string |
| rollup | query | Whether to return only highest-level "rollup" superseding solutions. | No | boolean |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSolution%C2%BB](#resources%c2%absolution%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities

#### GET
##### Summary

Vulnerabilities

##### Description

Returns all vulnerabilities that can be assessed during a scan.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerability%C2%BB](#pageof%c2%abvulnerability%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}

#### GET
##### Summary

Vulnerability

##### Description

Returns the details for a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Vulnerability](#vulnerability) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}/assets

#### GET
##### Summary

Vulnerability Affected Assets

##### Description

Get the assets affected by the vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABAssetID,Link%C2%BB](#referenceswith%c2%abassetid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}/exploits

#### GET
##### Summary

Vulnerability Exploits

##### Description

Returns the exploits that can be used to exploit a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABExploit%C2%BB](#pageof%c2%abexploit%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}/malware_kits

#### GET
##### Summary

Vulnerability Malware Kits

##### Description

Returns the malware kits that are known to be used to exploit the vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABMalwareKit%C2%BB](#pageof%c2%abmalwarekit%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}/references

#### GET
##### Summary

Vulnerability References

##### Description

Returns the external references that may be associated to a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityReference%C2%BB](#pageof%c2%abvulnerabilityreference%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerabilities/{id}/solutions

#### GET
##### Summary

Vulnerability Solutions

##### Description

Returns all solutions (across all platforms) that may be used to remediate this vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABSolutionNaturalID,Link%C2%BB](#referenceswith%c2%absolutionnaturalid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_categories

#### GET
##### Summary

Categories

##### Description

Returns all vulnerabilities categories that can be assigned to a vulnerability. These categories group and label vulnerabilities by general purpose, affected systems, vendor, etc.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityCategory%C2%BB](#pageof%c2%abvulnerabilitycategory%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_categories/{id}

#### GET
##### Summary

Category

##### Description

Returns the details for a vulnerability category.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability category. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityCategory](#vulnerabilitycategory) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_categories/{id}/vulnerabilities

#### GET
##### Summary

Category Vulnerabilities

##### Description

Returns hypermedia links to the vulnerabilities that are in a vulnerability category.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability category. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABVulnerabilityNaturalID,Link%C2%BB](#referenceswith%c2%abvulnerabilitynaturalid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_references

#### GET
##### Summary

References

##### Description

Returns the external references that may be associated to a vulnerability.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityReference%C2%BB](#pageof%c2%abvulnerabilityreference%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_references/{id}

#### GET
##### Summary

Reference

##### Description

Returns an external vulnerability reference.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability reference. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityReference](#vulnerabilityreference) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_references/{id}/vulnerabilities

#### GET
##### Summary

Reference Vulnerabilities

##### Description

Returns the vulnerabilities that are referenced by an external reference.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | id | Yes | integer |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerability%C2%BB](#pageof%c2%abvulnerability%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Report
Resources and operations for managing and generating reports. Reports are broadly categorized into `document`, `export`, and `file` types. `document` reports use section-based report templates to control the output and can be generated in several formats. `export` reports are designed to output their contents into a specific file format. `file` reports are templatized reports that output based on the format of a template file. Reports can be configured to generate on a schedule and be distributed via email to specific recipients.

### /api/3/report_formats

#### GET
##### Summary

Report Formats

##### Description

Returns all available report formats. A report format indicates an output file format specification (e.g. PDF, XML, etc). Some printable formats may be templated, and others may not. The supported templates for each formated are provided.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAvailableReportFormat%C2%BB](#resources%c2%abavailablereportformat%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/report_templates

#### GET
##### Summary

Report Templates

##### Description

Returns all available report templates.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABReportTemplate%C2%BB](#resources%c2%abreporttemplate%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/report_templates/{id}

#### GET
##### Summary

Report Template

##### Description

Returns the details of a report template. Report templates govern the contents generated within a report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report template; | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReportTemplate](#reporttemplate) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports

#### GET
##### Summary

Reports

##### Description

Returns all defined report configurations.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABReport%C2%BB](#pageof%c2%abreport%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Reports

##### Description

Configures a new report for generation. Report types are controlled through either or both a format and template. Non-templatized (`export`) report formats do not require a template and have their output format preset. Templatized (`document` and `file`) report formats support a report template that governs the content of the output and the output format can be chosen from a list of supported formats.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| report | body | The specification of a report configuration. | No | [Report](#report) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABint,Link%C2%BB](#createdreference%c2%abint,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports/{id}

#### GET
##### Summary

Report

##### Description

Returns the configuration details of a report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Report](#report) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Report

##### Description

Updates the configuration details of a report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |
| report | body | The specification of a report configuration. | No | [Report](#report) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Report

##### Description

Deletes the configuration of a report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports/{id}/generate

#### POST
##### Summary

Report Generation

##### Description

Generates a configured report and returns the instance identifier of the report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferenceWithReportIDLink](#referencewithreportidlink) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports/{id}/history

#### GET
##### Summary

Report Histories

##### Description

Returns all historical details for generation of the report over time.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABReportInstance%C2%BB](#resources%c2%abreportinstance%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports/{id}/history/{instance}

#### GET
##### Summary

Report History

##### Description

Returns the details for a generation of the report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |
| instance | path | The identifier of the report instance. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReportInstance](#reportinstance) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Report History

##### Description

Deletes an instance of a generated report.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |
| instance | path | The identifier of the report instance. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/reports/{id}/history/{instance}/output

#### GET
##### Summary

Report Download

##### Description

Returns the contents of a generated report. The report content is usually returned in a GZip compressed format.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the report. | Yes | integer |
| instance | path | The identifier of the report instance. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | byte |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Scan Engine
Resources and operations for managing scan engines.

### /api/3/scan_engine_pools

#### GET
##### Summary

Engine Pools

##### Description

Returns engine pools available to use for scanning.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABEnginePool%C2%BB](#resources%c2%abenginepool%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Engine Pools

##### Description

Creates a new engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| enginePool | body | The details for the scan engine to update. | No | [EnginePool](#enginepool) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABEngineID,Link%C2%BB](#createdreference%c2%abengineid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engine_pools/{id}

#### GET
##### Summary

Engine Pool

##### Description

Retrieves the details for an engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [EnginePool](#enginepool) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Engine Pool

##### Description

Updates the specified engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |
| enginePool | body | The details for the scan engine to update. | No | [EnginePool](#enginepool) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Engine Pool

##### Description

Deletes the specified engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engine_pools/{id}/engines

#### GET
##### Summary

Engine Pool Engines

##### Description

Get the engines in the engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABEngineID,Link%C2%BB](#referenceswith%c2%abengineid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Engine Pool Engines

##### Description

Set the engines in the engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |
| engines | body | The identifiers of the scan engines to place into the engine pool. | No | [ integer ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engine_pools/{id}/engines/{engineId}

#### PUT
##### Summary

Engine Pool Engines

##### Description

Add an engine to the engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |
| engineId | path | The identifier of the scan engine. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Engine Pool Engines

##### Description

Remove the specified engine from the engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |
| engineId | path | The identifier of the scan engine. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engine_pools/{id}/sites

#### GET
##### Summary

Engine Pool Sites

##### Description

Returns links to the sites associated with this engine pool.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the engine pool. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABSiteID,Link%C2%BB](#referenceswith%c2%absiteid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines

#### GET
##### Summary

Scan Engines

##### Description

Returns scan engines available to use for scanning.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABScanEngine%C2%BB](#resources%c2%abscanengine%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Scan Engines

##### Description

Creates a new scan engine.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanEngine | body | The specification of a scan engine. | No | [ScanEngine](#scanengine) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABEngineID,Link%C2%BB](#referencewith%c2%abengineid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/shared_secret

#### GET
##### Summary

Scan Engine Shared Secret

##### Description

Returns the current valid shared secret, if one has been previously generated and it has not yet expired; otherwise the endpoint will respond with a 404 status code. Use this endpoint to detect whether a previously-generated shared secret is still valid.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | string |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Scan Engine Shared Secret

##### Description

Returns the current valid shared secret or generates a new shared secret. The endpoint returns an existing shared secret if one was previously generated and it has not yet expired. Conversely, the endpoint will generate and return a new shared secret for either of the following conditions: a shared secret was not previously generated or the previously-generated shared secret has expired. The shared secret is valid for 60 minutes from the moment it is generated.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | string |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Scan Engine Shared Secret

##### Description

Revokes the current valid shared secret, if one exists.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/shared_secret/time_to_live

#### GET
##### Summary

Scan Engine Shared Secret Time to live

##### Description

Returns the number of seconds remaining for the current shared secret before it expires, if one has been previously generated and it has not yet expired; otherwise the endpoint will respond with a 404 status code.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | long |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/{id}

#### GET
##### Summary

Scan Engine

##### Description

Retrieves the details for a scan engine.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ScanEngine](#scanengine) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Scan Engine

##### Description

Updates the specified scan engine.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |
| scanEngine | body | The specification of the scan engine to update. | No | [ScanEngine](#scanengine) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Scan Engine

##### Description

Deletes the specified scan engine.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/{id}/scan_engine_pools

#### GET
##### Summary

Assigned Engine Pools

##### Description

Retrieves the list of engine pools the scan engine is currently assigned to.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABEnginePool%C2%BB](#resources%c2%abenginepool%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/{id}/scans

#### GET
##### Summary

Scan Engine Scans

##### Description

Returns the scans that have been run on a scan engine.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABScan%C2%BB](#pageof%c2%abscan%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_engines/{id}/sites

#### GET
##### Summary

Scan Engine Sites

##### Description

Retrieves the list of sites the specified scan engine is assigned to.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan engine. | Yes | integer |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABSite%C2%BB](#pageof%c2%absite%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
