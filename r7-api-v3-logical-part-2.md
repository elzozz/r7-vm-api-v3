## Site
Resources and operations for managing sites.

### /api/3/sites/{id}/assets

#### GET
##### Summary

Site Assets

##### Description

Retrieves a paged resource of assets linked with the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAsset%C2%BB](#pageof%c2%abasset%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Assets

##### Description

Creates or updates an asset with the specified details.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| asset | body | The details of the asset being added or updated.  The operating system can be specified in one of three ways, with the order of precedence: `"osFingerprint"`, `"os"`, `"cpe"` | No | [AssetCreate](#assetcreate) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference](#createdreference) |
| 201 | Created<br> | [CreatedOrUpdatedReference](#createdorupdatedreference) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Site Assets

##### Description

Removes all assets from the specified site. Assets will be deleted entirely from the Security Console if either Asset Linking is disabled or if Asset Linking is enabled and the asset only existed in this site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites

#### GET
##### Summary

Sites

##### Description

Retrieves a paged resource of accessible sites.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
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

#### POST
##### Summary

Sites

##### Description

Creates a new site with the specified configuration.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| site | body | Resource for creating a site configuration. | No | [SiteCreateResource](#sitecreateresource) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABSiteID,Link%C2%BB](#referencewith%c2%absiteid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}

#### GET
##### Summary

Site

##### Description

Retrieves the site with the specified identifier.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Site](#site) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site

##### Description

Updates the configuration of the site with the specified identifier.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| site | body | Resource for updating a site configuration. | No | [SiteUpdateResource](#siteupdateresource) |
| id | path | The identifier of the site. | Yes | integer |

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

Site

##### Description

Deletes the site with the specified identifier.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts

#### GET
##### Summary

Site Alerts

##### Description

Retrieve all alerts defined in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAlert%C2%BB](#resources%c2%abalert%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Site Alerts

##### Description

Deletes all alerts from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/smtp

#### GET
##### Summary

Site SMTP Alerts

##### Description

Retrieves all SMTP alerts defined in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSmtpAlert%C2%BB](#resources%c2%absmtpalert%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site SMTP Alerts

##### Description

Creates a new SMTP alert for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for creating a new SMTP alert. | No | [SmtpAlert](#smtpalert) |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABAlertID,Link%C2%BB](#referencewith%c2%abalertid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site SMTP Alerts

##### Description

Updates all SMTP alerts for the specified site in a single request using the array of resources defined in the request body.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Array of resources for updating all SMTP alerts defined in the site. Alerts defined in the site that are omitted from this request will be deleted from the site. | No | [ [SmtpAlert](#smtpalert) ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site SMTP Alerts

##### Description

Deletes all SMTP alerts from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/smtp/{alertId}

#### GET
##### Summary

Site SMTP Alert

##### Description

Retrieves the specified SMTP alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SmtpAlert](#smtpalert) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site SMTP Alert

##### Description

Updates the specified SMTP alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for updating the specified SMTP alert. | No | [SmtpAlert](#smtpalert) |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

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

Site SMTP Alert

##### Description

Deletes the specified SMTP alert from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/snmp

#### GET
##### Summary

Site SNMP Alerts

##### Description

Retrieves all SNMP alerts defined in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSnmpAlert%C2%BB](#resources%c2%absnmpalert%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site SNMP Alerts

##### Description

Creates a new SNMP alert for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for creating a new SNMP alert. | No | [SnmpAlert](#snmpalert) |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABAlertID,Link%C2%BB](#referencewith%c2%abalertid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site SNMP Alerts

##### Description

Updates all SNMP alerts for the specified site in a single request using the array of resources defined in the request body.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Array of resources for updating all SNMP alerts defined in the site. Alerts defined in the site that are omitted from this request will be deleted from the site. | No | [ [SnmpAlert](#snmpalert) ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site SNMP Alerts

##### Description

Deletes all SNMP alerts from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/snmp/{alertId}

#### GET
##### Summary

Site SNMP Alert

##### Description

Retrieves the specified SNMP alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SnmpAlert](#snmpalert) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site SNMP Alert

##### Description

Updates the specified SNMP alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for updating the specified SNMP alert. | No | [SnmpAlert](#snmpalert) |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

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

Site SNMP Alert

##### Description

Deletes the specified SNMP alert from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/syslog

#### GET
##### Summary

Site Syslog Alerts

##### Description

Retrieves all Syslog alerts defined in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSyslogAlert%C2%BB](#resources%c2%absyslogalert%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Syslog Alerts

##### Description

Creates a new Syslog alert for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for creating a new Syslog alert. | No | [SyslogAlert](#syslogalert) |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABAlertID,Link%C2%BB](#referencewith%c2%abalertid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Syslog Alerts

##### Description

Updates all Syslog alerts for the specified site in a single request using the array of resources defined in the request body.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Array of resources for updating all Syslog alerts defined in the site. Alerts defined in the site that are omitted from this request will be deleted from the site. | No | [ [SyslogAlert](#syslogalert) ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Syslog Alerts

##### Description

Deletes all Syslog alerts from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/alerts/syslog/{alertId}

#### GET
##### Summary

Site Syslog Alert

##### Description

Retrieves the specified Syslog alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SyslogAlert](#syslogalert) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Syslog Alert

##### Description

Updates the specified Syslog alert.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| alert | body | Resource for updating the specified Syslog alert. | No | [SyslogAlert](#syslogalert) |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

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

Site Syslog Alert

##### Description

Deletes the specified Syslog alert from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| alertId | path | The identifier of the alert. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/assets/{assetId}

#### DELETE
##### Summary

Site Asset

##### Description

Removes an asset from a site. The asset will only be deleted if it belongs to no other sites.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/discovery_connection

#### GET
##### Summary

Site Discovery Connection

##### Description

Retrieves the discovery connection assigned to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SiteDiscoveryConnection](#sitediscoveryconnection) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Discovery Connection

##### Description

Updates the discovery connection assigned to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| connectionId | body | The identifier of the discovery connection. | No | long |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/discovery_search_criteria

#### GET
##### Summary

Site Discovery Search Criteria

##### Description

Retrieve the search criteria of the dynamic site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [DiscoverySearchCriteria](#discoverysearchcriteria) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Discovery Search Criteria

##### Description

Update the search criteria of the dynamic site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| param1 | body | param1 | Yes | [DiscoverySearchCriteria](#discoverysearchcriteria) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/excluded_asset_groups

#### GET
##### Summary

Site Excluded Asset Groups

##### Description

Retrieves the excluded asset groups in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAssetGroup%C2%BB](#resources%c2%abassetgroup%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Excluded Asset Groups

##### Description

Updates the excluded asset groups in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetGroupIds | body | Array of asset group identifiers. | No | [ integer ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Excluded Asset Groups

##### Description

Removes all excluded asset groups from the specified static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/excluded_asset_groups/{assetGroupId}

#### DELETE
##### Summary

Site Excluded Asset Group

##### Description

Removes the specified asset group from the excluded asset groups configured in the static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| assetGroupId | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/excluded_targets

#### GET
##### Summary

Site Excluded Targets

##### Description

Retrieves the excluded targets in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ScanTargetsResource](#scantargetsresource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Excluded Targets

##### Description

Adds one or more addresses to the site's list of excluded scan targets.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scanTargetsToAdd | body | List of addresses to add to the site's excluded scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABSiteID,Link%C2%BB](#referencewith%c2%absiteid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Excluded Targets

##### Description

Updates the excluded targets in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanTargets | body | List of addresses to be the site's new excluded scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Excluded Targets

##### Description

Removes one or more addresses from the site's list of excluded scan targets.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scanTargetsToRemove | body | List of address to remove from the sites excluded scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/included_asset_groups

#### GET
##### Summary

Site Included Asset Groups

##### Description

Retrieves the included asset groups in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAssetGroup%C2%BB](#resources%c2%abassetgroup%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Included Asset Groups

##### Description

Updates the included asset groups in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetGroupIds | body | Array of asset group identifiers. | No | [ integer ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Included Asset Groups

##### Description

Removes all included asset groups from the specified static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/included_asset_groups/{assetGroupId}

#### DELETE
##### Summary

Site Included Asset Group

##### Description

Removes the specified asset group from the included asset groups configured in the static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| assetGroupId | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/included_targets

#### GET
##### Summary

Site Included Targets

##### Description

Retrieves the included targets in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ScanTargetsResource](#scantargetsresource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Included Targets

##### Description

Adds one or more addresses to the site's list of included scan targets.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scanTargetsToAdd | body | List of addresses to add to the site's included scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABSiteID,Link%C2%BB](#referencewith%c2%absiteid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Included Targets

##### Description

Updates the included targets in a static site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanTargets | body | List of addresses to be the site's new included scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Included Targets

##### Description

Removes one or more addresses from the site's list of included scan targets.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scanTargetsToRemove | body | List of address to remove from the sites included scan targets. Each address is a string that can represent either a hostname, ipv4 address, ipv4 address range, ipv6 address, or CIDR notation. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/organization

#### GET
##### Summary

Site Organization Information

##### Description

Retrieves the site organization information.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SiteOrganization](#siteorganization) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Organization Information

##### Description

Updates the site organization information.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| siteOrganization | body | Resource for updating the specified site's organization information. | No | [SiteOrganization](#siteorganization) |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/scan_engine

#### GET
##### Summary

Site Scan Engine

##### Description

Retrieves the resource of the scan engine assigned to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

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

Site Scan Engine

##### Description

Updates the assigned scan engine to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanEngineId | body | The identifier of the scan engine. | No | integer |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/scan_schedules

#### GET
##### Summary

Site Scan Schedules

##### Description

Returns all scan schedules for the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABScanSchedule%C2%BB](#resources%c2%abscanschedule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Scan Schedules

##### Description

Creates a new scan schedule for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanSchedule | body | Resource for a scan schedule. | No | [ScanSchedule](#scanschedule) |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABScanScheduleID,Link%C2%BB](#referencewith%c2%abscanscheduleid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Scan Schedules

##### Description

Updates all scan schedules for the specified site in a single request using the array of resources defined in the request body.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanSchedules | body | Array of resources for updating all scan schedules defined in the site. Scan schedules defined in the site that are omitted from this request will be deleted from the site. | No | [ [ScanSchedule](#scanschedule) ] |
| id | path | The identifier of the site. | Yes | integer |

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

Site Scan Schedules

##### Description

Deletes all scan schedules from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/scan_schedules/{scheduleId}

#### GET
##### Summary

Site Scan Schedule

##### Description

Retrieves the specified scan schedule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scheduleId | path | The identifier of the scan schedule. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ScanSchedule](#scanschedule) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Scan Schedule

##### Description

Updates the specified scan schedule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanSchedule | body | Resource for updating the specified scan schedule. | No | [ScanSchedule](#scanschedule) |
| id | path | The identifier of the site. | Yes | integer |
| scheduleId | path | The identifier of the scan schedule. | Yes | integer |

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

Site Scan Schedule

##### Description

Deletes the specified scan schedule from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| scheduleId | path | The identifier of the scan schedule. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/scan_template

#### GET
##### Summary

Site Scan Template

##### Description

Retrieves the resource of the scan template assigned to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ScanTemplate](#scantemplate) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Scan Template

##### Description

Updates the assigned scan template to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanTemplateId | body | The identifier of the scan template. | No | string |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/shared_credentials

#### GET
##### Summary

Assigned Shared Credentials

##### Description

Retrieve all of the shared credentials assigned to the site. These shared credentials can be enabled/disabled for the site's scan.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSiteSharedCredential%C2%BB](#resources%c2%absitesharedcredential%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/shared_credentials/{credentialId}/enabled

#### PUT
##### Summary

Assigned Shared Credential Enablement

##### Description

Enable or disable the shared credential for the site's scans.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| status | body | Flag indicating whether the shared credential is enabled for the site's scans. | No | boolean |
| id | path | The identifier of the site. | Yes | integer |
| credentialId | path | The identifier of the shared credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/site_credentials

#### GET
##### Summary

Site Scan Credentials

##### Description

Retrieves all defined site credential resources.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSiteCredential%C2%BB](#resources%c2%absitecredential%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Scan Credentials

##### Description

Creates a new site credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| siteCredential | body | The specification of a site credential. | No | [SiteCredential](#sitecredential) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [CreatedReference%C2%ABCredentialID,Link%C2%BB](#createdreference%c2%abcredentialid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Scan Credentials

##### Description

Updates multiple site credentials.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| siteCredentials | body | A list of site credentials resources. | No | [ [SiteCredential](#sitecredential) ] |

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

Site Scan Credentials

##### Description

Deletes all site credentials from the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/site_credentials/{credentialId}

#### GET
##### Summary

Site Scan Credential

##### Description

Retrieves the specified site credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| credentialId | path | The identifier of the site credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SiteCredential](#sitecredential) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Scan Credential

##### Description

Updates the specified site credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| credentialId | path | The identifier of the site credential. | Yes | integer |
| siteCredential | body | The specification of the site credential to update. | No | [SiteCredential](#sitecredential) |

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

Site Scan Credential

##### Description

Deletes the specified site credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| credentialId | path | The identifier of the site credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/site_credentials/{credentialId}/enabled

#### PUT
##### Summary

Site Credential Enablement

##### Description

Enable or disable the site credential for scans.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| status | body | Flag indicating whether the credential is enabled for use during the scan. | No | boolean |
| id | path | The identifier of the site. | Yes | integer |
| credentialId | path | The identifier of the site credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/tags

#### GET
##### Summary

Site Tags

##### Description

Retrieves the list of tags added to the sites.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABTag%C2%BB](#resources%c2%abtag%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Tags

##### Description

Updates the site's list of tags.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| tags | body | A list of tag identifiers to replace the site's tags. | No | [ integer ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/tags/{tagId}

#### PUT
##### Summary

Site Tag

##### Description

Adds a tag to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| tagId | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Site Tag

##### Description

Removes the specified tag from the site's tags.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| tagId | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/users

#### GET
##### Summary

Site Users Access

##### Description

Retrieve the list of non-administrator users that have access to the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABUser%C2%BB](#resources%c2%abuser%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Site Users Access

##### Description

Grants a non-administrator user access to the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| param0 | body | The identifier of the user. | No | integer |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABUserID,Link%C2%BB](#referencewith%c2%abuserid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Site Users Access

##### Description

Updates the site's access list.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| users | body | A list of user identifiers to replace the site's access list. | No | [ integer ] |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/users/{userId}

#### DELETE
##### Summary

Site User Access

##### Description

Removes the specified user from the site's access list.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| userId | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/web_authentication/html_forms

#### GET
##### Summary

Web Authentication HTML Forms

##### Description

Retrieves all HTML form authentications configured in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABWebFormAuthentication%C2%BB](#resources%c2%abwebformauthentication%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/web_authentication/http_headers

#### GET
##### Summary

Web Authentication HTTP Headers

##### Description

Retrieves all HTTP header authentications configured in the site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABWebHeaderAuthentication%C2%BB](#resources%c2%abwebheaderauthentication%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Policy
Resources and operations for managing policies.

### /api/3/assets/{assetId}/policies

#### GET
##### Summary

Policies For Asset

##### Description

Retrieves the list of policies with compliance results for the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetId | path | The identifier of the asset. | Yes | long |
| applicableOnly | query | An optional boolean parameter indicating the policies retrieved should only include those with a policy compliance status of either a PASS of FAIL result. Default value is `false`, which will also include policies with a compliance status of NOT_APPLICABLE. | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAssetPolicy%C2%BB](#pageof%c2%abassetpolicy%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{assetId}/policies/{policyId}/children

#### GET
##### Summary

Policy Rules or Groups Directly Under Policy For Asset

##### Description

Retrieves a paged resource of either policy rules, or groups, that are defined directly underneath the specified policy with rule compliance results for the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetId | path | The identifier of the asset. | Yes | long |
| policyId | path | The identifier of the policy | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAssetPolicyItem%C2%BB](#pageof%c2%abassetpolicyitem%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{assetId}/policies/{policyId}/groups/{groupId}/children

#### GET
##### Summary

Policy Rules or Groups Directly Under Policy Group For Asset

##### Description

Retrieves a paged resource of either policy rules, or groups, that are defined directly underneath the specified policy group with rule compliance results for the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetId | path | The identifier of the asset. | Yes | long |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAssetPolicyItem%C2%BB](#pageof%c2%abassetpolicyitem%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{assetId}/policies/{policyId}/groups/{groupId}/rules

#### GET
##### Summary

Policy Rules Under Policy Group For Asset

##### Description

Retrieves the list of policy rules defined directly, or indirectly, underneath the specified policy group and the compliance results for the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetId | path | The identifier of the asset. | Yes | long |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyRule%C2%BB](#pageof%c2%abpolicyrule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{assetId}/policies/{policyId}/rules

#### GET
##### Summary

Policy Rules For Asset

##### Description

Retrieves the list of policy rules with compliance results for the specified asset and policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetId | path | The identifier of the asset. | Yes | long |
| policyId | path | The identifier of the policy | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyRule%C2%BB](#pageof%c2%abpolicyrule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies

#### GET
##### Summary

Policies

##### Description

Retrieves a paged resource of policies.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| filter | query | Filters the retrieved policies with those whose titles that match the parameter. | No | string |
| scannedOnly | query | Flag indicating the policies retrieved should only include those with Pass or Fail compliance results. The list of scanned policies is based on the user's list of accessible assets. | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicy%C2%BB](#pageof%c2%abpolicy%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{id}/children

#### GET
##### Summary

Policy Rules or Groups Directly Under Policy

##### Description

Retrieves a paged resource of either policy rules, or groups, that are defined directly underneath the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the policy | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyItem%C2%BB](#pageof%c2%abpolicyitem%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}

#### GET
##### Summary

Policy

##### Description

Retrieves the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Policy](#policy) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/assets

#### GET
##### Summary

Policy Asset Results

##### Description

Retrieves asset resources with rule compliance results for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| applicableOnly | query | An optional boolean parameter indicating the assets retrieved should only include those with rule results of either PASS or FAIL. Default value is `false`, which will also include assets with a compliance status of NOT_APPLICABLE. | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyAsset%C2%BB](#pageof%c2%abpolicyasset%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/assets/{assetId}

#### GET
##### Summary

Policy Asset Result

##### Description

Retrieves an asset resource with rule compliance results for the specified asset and policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyAsset](#policyasset) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups

#### GET
##### Summary

Policy Groups

##### Description

Retrieves a paged resource of policy groups for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyGroup%C2%BB](#pageof%c2%abpolicygroup%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups/{groupId}

#### GET
##### Summary

Policy Group

##### Description

Retrieves the specified policy group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyGroup](#policygroup) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups/{groupId}/assets

#### GET
##### Summary

Assets Compliance For Policy Rules Under Policy Group

##### Description

Retrieves asset resources with rule compliance status against all rules under the specified policy group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |
| applicableOnly | query | An optional boolean parameter indicating the assets retrieved should only include those with rule results of either PASS or FAIL. Default value is `false`, which will also include assets with a compliance status of NOT_APPLICABLE. | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyAsset%C2%BB](#pageof%c2%abpolicyasset%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups/{groupId}/assets/{assetId}

#### GET
##### Summary

Asset Compliance For Policy Rules Under Policy Group

##### Description

Retrieves an asset resource with rule compliance status against all rules under the specified policy group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyAsset](#policyasset) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups/{groupId}/children

#### GET
##### Summary

Policy Rules or Groups Directly Under Policy Group

##### Description

Retrieves a paged resource of either policy rules, or groups, that are defined directly underneath the specified policy group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyItem%C2%BB](#pageof%c2%abpolicyitem%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/groups/{groupId}/rules

#### GET
##### Summary

Policy Rules Under Policy Group

##### Description

Retrieves the list of policy rules defined directly, or indirectly, underneath the specified policy group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| groupId | path | The identifier of the policy group. | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyRule%C2%BB](#pageof%c2%abpolicyrule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules

#### GET
##### Summary

Policy Rules

##### Description

Retrieves a paged resource of policy rules for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyRule%C2%BB](#pageof%c2%abpolicyrule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/disabled

#### GET
##### Summary

Disabled Policy Rules

##### Description

Retrieves a paged resource of disabled policy rules for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyRule%C2%BB](#pageof%c2%abpolicyrule%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}

#### GET
##### Summary

Policy Rule

##### Description

Retrieves the specified policy rule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyRule](#policyrule) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/assets

#### GET
##### Summary

Assets Compliance For Policy Rule

##### Description

Retrieves asset resources with rule compliance results for the specified policy policy rule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |
| applicableOnly | query | An optional boolean parameter indicating the assets retrieved should only include those with rule results of either PASS or FAIL. Default value is `false`, which will also include assets with a compliance status of NOT_APPLICABLE. | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyAsset%C2%BB](#pageof%c2%abpolicyasset%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/assets/{assetId}

#### GET
##### Summary

Asset Compliance For Policy Rule

##### Description

Retrieves an asset resource with rule compliance results for the specified policy policy rule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicyAsset](#policyasset) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/assets/{assetId}/proof

#### GET
##### Summary

Policy Rule Proof For Asset

##### Description

Retrieves the policy rule proof captured during evaluation against the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | string |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/controls

#### GET
##### Summary

Policy Rule Controls

##### Description

Retrieves all NIST SP 800-53 controls mappings for each CCE within the specified policy rule.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABPolicyControl%C2%BB](#pageof%c2%abpolicycontrol%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/rationale

#### GET
##### Summary

Policy Rule Rationale

##### Description

Retrieves the policy rule rationale for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | string |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policies/{policyId}/rules/{ruleId}/remediation

#### GET
##### Summary

Policy Rule Remediation

##### Description

Retrieves the policy rule remediation for the specified policy.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| policyId | path | The identifier of the policy | Yes | long |
| ruleId | path | The identifier of the policy rule. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | string |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/policy/summary

#### GET
##### Summary

Policy Compliance Summaries

##### Description

Retrieves a compliance summary of all policies.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PolicySummaryResource](#policysummaryresource) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
