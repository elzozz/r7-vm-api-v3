## Scan Template
Scan Template Resource Controller

### /api/3/scan_templates

#### GET
##### Summary

Scan Templates

##### Description

Returns all scan templates.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABScanTemplate%C2%BB](#resources%c2%abscantemplate%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Scan Templates

##### Description

Creates a new scan template.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| scanTemplate | body | The details of the scan template. | No | [ScanTemplate](#scantemplate) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABScanTemplateID,Link%C2%BB](#createdreference%c2%abscantemplateid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scan_templates/{id}

#### GET
##### Summary

Scan Template

##### Description

Returns a scan template.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan template | Yes | string |

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

Scan Template

##### Description

Updates a scan template.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan template | Yes | string |
| scanTemplate | body | The details of the scan template. | No | [ScanTemplate](#scantemplate) |

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

Scan Template

##### Description

Deletes a scan template.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan template | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Scan
Resources and operations for managing scans.

### /api/3/scans

#### GET
##### Summary

Scans

##### Description

Returns all scans.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| active | query | Return running scans or past scans (true/false value). | No | boolean |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABGlobalScan%C2%BB](#pageof%c2%abglobalscan%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scans/{id}

#### GET
##### Summary

Scan

##### Description

Returns the specified scan.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Scan](#scan) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/scans/{id}/{status}

#### POST
##### Summary

Scan Status

##### Description

Updates the scan status. Can pause, resume, and stop scans using this resource. In order to stop a scan the scan must be running or paused. In order to resume a scan the scan must be paused. In order to pause a scan the scan must be running.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the scan. | Yes | long |
| status | path | The status of the scan. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/sites/{id}/scans

#### GET
##### Summary

Site Scans

##### Description

Returns the scans for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| active | query | Return running scans or past scans (true/false value). | No | boolean |
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

#### POST
##### Summary

Site Scans

##### Description

Starts a scan for the specified site.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the site. | Yes | integer |
| overrideBlackout | query | Whether to request for the override of an scan blackout window. | No | boolean |
| scan | body | The details for the scan. | No | [AdhocScan](#adhocscan) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABScanID,Link%C2%BB](#createdreference%c2%abscanid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Credential
Resources and operations for managing shared credentials.

### /api/3/shared_credentials

#### GET
##### Summary

Shared Credentials

##### Description

Retrieves all defined shared credential resources.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSharedCredential%C2%BB](#resources%c2%absharedcredential%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Shared Credentials

##### Description

Creates a new shared credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| credential | body | The specification of a shared credential. | No | [SharedCredential](#sharedcredential) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [CreatedReference%C2%ABCredentialID,Link%C2%BB](#createdreference%c2%abcredentialid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Shared Credentials

##### Description

Deletes all shared credentials.

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

### /api/3/shared_credentials/{id}

#### GET
##### Summary

Shared Credential

##### Description

Retrieves the specified shared credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SharedCredential](#sharedcredential) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Shared Credential

##### Description

Updates the specified shared credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the credential. | Yes | integer |
| credential | body | The specification of the shared credential to update. | No | [SharedCredential](#sharedcredential) |

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

Shared Credential

##### Description

Deletes the specified shared scan credential.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the credential. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Tag
Resources and operations for managing tags.

### /api/3/tags

#### GET
##### Summary

Tags

##### Description

Returns all tags.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| name | query | name | No | string |
| type | query | type | No | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABTag%C2%BB](#pageof%c2%abtag%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Tags

##### Description

Creates a new tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| tag | body | The details of the tag. | No | [Tag](#tag) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [ReferenceWith%C2%ABTagID,Link%C2%BB](#referencewith%c2%abtagid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}

#### GET
##### Summary

Tag

##### Description

Returns a tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Tag](#tag) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Tag

##### Description

Updates the details of a tag. For more information about accepted fields for the tag search criteria see the PUT /search_criteria documentation.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| tag | body | The details of the tag. | No | [Tag](#tag) |
| id | path | The identifier of the tag. | Yes | integer |

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

Tag

##### Description

Deletes the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/asset_groups

#### GET
##### Summary

Tag Asset Groups

##### Description

Returns the asset groups associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

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

Tag Asset Groups

##### Description

Sets the asset groups associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| assetGroupIds | body | The asset groups to add to the tag. | No | [ integer ] |

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

Tag Asset Groups

##### Description

Removes the associations between the tag and all asset groups.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/asset_groups/{assetGroupId}

#### PUT
##### Summary

Tag Asset Group

##### Description

Adds an asset group to this tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| assetGroupId | path | The asset group identifier. | Yes | integer |

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

Tag Asset Group

##### Description

Removes an asset group from this tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| assetGroupId | path | The asset group identifier. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/assets

#### GET
##### Summary

Tag Assets

##### Description

Returns the assets tagged with a tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [TaggedAssetReferences](#taggedassetreferences) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/assets/{assetId}

#### PUT
##### Summary

Tag Asset

##### Description

Adds an asset to the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| assetId | path | The identifier of the asset. | Yes | long |

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

Tag Asset

##### Description

Removes an asset from the tag. Note: The asset must be added through the asset or tag, if the asset is added using a site, asset group, or search criteria this will not remove the asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/search_criteria

#### GET
##### Summary

Tag Search Criteria

##### Description

Returns the search criteria associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [SearchCriteria](#searchcriteria) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Tag Search Criteria

##### Description

Updates the search criteria associated with the tag.

The following table outlines the search criteria fields and the available operators:
\| Field \| Operators \|
\| ---------- \| ---------------- \|
\| ip-address \| is, is-not, in-range, not-in-range, is-like, not-like \|
\| ip-address-type \| in, not-in \|
\| alternate-address-type \| in \|
\| host-name \| is, is-not, starts-with, ends-with, contains, does-not-contain, is-empty, is-not-empty, is-like, not-like \|
\| host-type \| in, not-in \|
\| operating-system \| contains, does-not-contain, is-empty, is-not-empty \|
\| software \| contains, does-not-contain\|
\| open-ports \| is, is-not, in-range \|
\| service-name \| contains, does-not-contain \|
\| risk-score \| is, is-not, in-range, is-greater-than,is-less-than \|
\| last-scan-date \| is-on-or-before, is-on-or-after, is-between, is-earlier-than, is-within-the-last \|
\| vulnerability-assessed \| is-on-or-before, is-on-or-after, is-between, is-earlier-than, is-within-the-last \|
\| vulnerability-category \| is, is-not, starts-with, ends-with, contains, does-not-contain\|
\| vulnerability-cvss-score \| is, is-not, in-range, is-greater-than, is-less-than \|
\| vulnerability-cvss-v3-score \| is, is-not, in-range, is-greater-than, is-less-than \|
\| vulnerability-exposures \| includes, does not-include \|
\| vulnerability-title \| contains, does-not-contain, is, is-not, starts-with, ends-with \|
\| cve \| is, is-not, contains, does-not-contain \|
\| cvss-access-complexity \| is, is-not \|
\| cvss-authentication-required \| is, is-not \|
\| cvss-access-vector \| is, is-not \|
\| cvss-availability-impact \| is, is-not \|
\| cvss-confidentiality-impact \| is, is-not \|
\| cvss-integrity-impact \| is, is-not \|
\| cvss-v3-confidentiality-impact \| is, is-not \|
\| cvss-v3-integrity-impact \| is, is-not \|
\| cvss-v3-availability-impact \| is, is-not \|
\| cvss-v3-attack-vector \| is, is-not \|
\| cvss-v3-attack-complexity \| is, is-not \|
\| cvss-v3-user-interaction \| is, is-not \|
\| cvss-v3-privileges-required \| is, is-not \|
\| mobile-device-last-sync \| is-within-the-last, is-earlier-than \|
\| pci-compliance \| is \|
\| site-id \| in, not-in \|
\| criticality-tag \| is, is-not, is-greater-than, is-less-than, is-applied, is-not-applied \|
\| custom-tag \| is, is-not, starts-with, ends-with, contains, does-not-contain, is-applied, is-not-applied \|
\| location-tag \| is, is-not, starts-with, ends-with, contains, does-not-contain, is-applied, is-not-applied \|
\| owner-tag \| is, is-not, starts-with, ends-with, contains, does-not-contain, is-applied, is-not-applied \|
\| vulnerability-validated-status \| are \|
\| vasset-cluster \| is, is-not, contains, does-not-contain, starts-with \|
\| vasset-datacenter \| is, is-not \|
\| vasset-host name \| is, is-not, contains, does-not-contain, starts-with \|
\| vasset-power state \| in, not-in \|
\| vasset-resource pool path \| contains, does-not-contain \|
\| container-image \| is, is-not, starts-with, ends-with, contains, does-not-contain, is-like, not-like \|
\| container-status \| is, is-not \|
\| containers \| are \|

The following table outlines the operators and the values associated with them:
\| Operator \| Values \|
\| -------- \| ------ \|
\| are \| A single string property named "value" \|
\| is-between \| A number property named "lower" and a number property named "upper" \|
\| contains \| A single string property named "value" \|
\| does-not-contain \| A single string property named "value" \|
\| is-earlier-than \| A single number property named "value" \|
\| ends-with \| A single string property named "value" \|
\| is-greater-than \| A single number property named "value" \|
\| in \| An array property named "values" \|
\| not-in \| An array property named "values" \|
\| in-range \| A number property named "lower" and a number property named "upper" \|
\| includes \| An array property named "values" \|
\| is \| A single string property named "value" \|
\| is-not \| A single string property named "value" \|
\| is-applied \| No value \|
\| is-not-applied \| No value \|
\| is-empty \| No value \|
\| is-not-empty \| No value \|
\| is-less-than \| A single number property named "value" \|
\| is-like \| A single string property named "value" \|
\| does-not-contain \| A single string property named "value" \|
\| not-in-range \| A number property named "lower" and a number property named "upper" \|
\| not-like \| A single string property named "value" \|
\| is-on-or-after \| A single string property named "value", which is the date in ISO8601 format (yyyy-MM-dd) \|
\| is-on-or-before \| A single string property named "value", which is the date in ISO8601 format (yyyy-MM-dd) \|
\| starts-with \| A single string property named "value" \|
\| is-within-the-last \| A single number property named "value" \|

The following fields have enumerated values:
\| Field \| Acceptable Values \|
\| ----- \| ----------------- \|
\| containers \| 0=present, 1=not present \|
\| vulnerability-validated-status \| 0=present, 1=not present \|
\| pci-compliance \| 0=fail, 1=pass \|
\| alternate-address-type \| 0=IPv4, 1=IPv6 \|
\| ip-address-type \| 0=IPv4, 1=IPv6 \|
\| host-type \| 0=Unknown, 1=Guest, 2=Hypervisor, 3=Physical, 4=Mobile \|
\| cvss-access-complexity \| L=Low, M=Medium, H=High \|
\| cvss-integrity-impact \| N=None, P=Partial, C=Complete \|
\| cvss-confidentiality-impact \| N=None, P=Partial, C=Complete \|
\| cvss-availability-impact \| N=None, P=Partial, C=Complete \|
\| cvss-access-vector \| L=Local, A=Adjacent, N=Network \|
\| cvss-authentication-required \| N=None, S=Single, M=Multiple \|
\| cvss-access-complexity \| L=Low, M=Medium, H=High \|
\| cvss-v3-confidentiality-impact \| N=None, L=Low, H=High \|
\| cvss-v3-integrity-impact \| N=None, L=Low, H=High \|
\| cvss-v3-availability-impact \| N=None, L=Low, H=High \|
\| cvss-v3-attack-vector \| N=Network, A=Adjacent, L=Local, P=Physical \|
\| cvss-v3-attack-complexity \| L=Low, H=High \|
\| cvss-v3-user-interaction \| N=None, R=Required \|
\| cvss-v3-privileges-required \| N=None, L=Low, H=High \|
\| container-status \| created, running, paused, restarting, exited, dead, unknown \|

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| criterial | body | The details of the search criteria. | No | [SearchCriteria](#searchcriteria) |

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

Tag Search Criteria

##### Description

Removes the search criteria associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/sites

#### GET
##### Summary

Tag Sites

##### Description

Returns the sites associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

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

Tag Sites

##### Description

Sets the sites associated with the tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
| sites | body | The sites to add to the tag. | No | [ integer ] |

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

Tag Sites

##### Description

Removes the associations between the tag and the sites.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/tags/{id}/sites/{siteId}

#### PUT
##### Summary

Tag Site

##### Description

Adds a site to this tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
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

Tag Site

##### Description

Removes a site from this tag.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the tag. | Yes | integer |
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
## Vulnerability Check
Resources and operations for view vulnerability checks that can be run as a part of vulnerability content.

### /api/3/vulnerabilities/{id}/checks

#### GET
##### Summary

Vulnerability Checks

##### Description

Returns the vulnerability checks that assess for a specific vulnerability during a scan.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABVulnerabilityCheckID,Link%C2%BB](#referenceswith%c2%abvulnerabilitycheckid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_checks

#### GET
##### Summary

Checks

##### Description

Returns vulnerability checks. Optional search and filtering parameters may be supplied to refine the results. Searching allows full text search of the vulnerability details a check is related to.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| search | query | Vulnerability search term to find vulnerability checks for. e.g. `"ssh"`. | No | string |
| safe | query | Whether to return vulnerability checks that are considered "safe" to run. Defaults to return safe and unsafe checks. | No | boolean |
| potential | query | Whether to only return checks that result in potentially vulnerable results. Defaults to return all checks. | No | boolean |
| requiresCredentials | query | Whether to only return checks that require credentials in order to successfully execute. Defaults to return all checks. | No | boolean |
| unique | query | Whether to only return checks that guarantee to be executed once-and-only once on a host resulting in a unique result. False returns checks that can result in multiple occurrences of the same vulnerability on a host. | No | boolean |
| type | query | The type of vulnerability checks to return. See <a href="#operation/vulnerabilityCheckTypesUsingGET">Check Types</a> for all available types. | No | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABVulnerabilityCheck%C2%BB](#pageof%c2%abvulnerabilitycheck%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_checks/{id}

#### GET
##### Summary

Check

##### Description

Returns the vulnerability check.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the vulnerability check. | Yes | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [VulnerabilityCheck](#vulnerabilitycheck) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/vulnerability_checks_types

#### GET
##### Summary

Check Types

##### Description

Returns the vulnerability check types. The type groups related vulnerability checks by their purpose, property, or related characteristic.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABVulnerabilityCheckTypeID,Link%C2%BB](#referenceswith%c2%abvulnerabilitychecktypeid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
