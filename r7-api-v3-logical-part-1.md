# InsightVM API
# Overview

This guide documents the InsightVM Application Programming Interface (API) Version 3. This API supports the
Representation State Transfer (REST) design pattern. Unless noted otherwise this API accepts and produces the
`application/json` media type. This API uses Hypermedia as the Engine of Application State (HATEOAS) and
is hypermedia friendly. All API connections must be made to the security console using HTTPS.

## Versioning

Versioning is specified in the URL and the base path of this API is: `https://<host>:<port>/api/3/`.

## Specification

An <a target="_blank" rel="noopener noreferrer" href="https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md">OpenAPI v2</a> specification (also
known as Swagger 2) of this API is available. Tools such as <a target="_blank" rel="noopener noreferrer" href="https://github.com/swagger-api/swagger-codegen">swagger-codegen</a>
can be used to generate an API client in the language of your choosing using this specification document.

<p class="openapi">Download the specification: <a class="openapi-button" target="_blank" rel="noopener noreferrer" download="" href="/insightvm/en-us/api/api-v3.json"> Download </a></p>

## Authentication

Authorization to the API uses HTTP Basic Authorization
(see <a target="_blank" rel="noopener noreferrer" href="https://www.ietf.org/rfc/rfc2617.txt">RFC 2617</a> for more information). Requests must
supply authorization credentials in the `Authorization` header using a Base64 encoded hash of `"username:password"`.

<!-- ReDoc-Inject: <security-definitions> -->

### 2FA

This API supports two-factor authentication (2FA) by supplying an authentication token in addition to the Basic
Authorization. The token is specified using the `Token` request header. To leverage two-factor authentication, this
must be enabled on the console and be configured for the account accessing the API.

## Resources

### Naming

Resource names represent nouns and identify the entity being manipulated or accessed. All collection resources are
pluralized to indicate to the client they are interacting with a collection of multiple resources of the same type.
Singular resource names are used when there exists only one resource available to interact with.

The following naming conventions are used by this API:

\| Type                                          \| Case                     \|
\| --------------------------------------------- \| ------------------------ \|
\| Resource names                                \| `lower_snake_case`       \|
\| Header, body, and query parameters parameters \| `camelCase`              \|
\| JSON fields and property names                \| `camelCase`              \|

#### Collections

A collection resource is a parent resource for instance resources, but can itself be retrieved and operated on
independently. Collection resources use a pluralized resource name. The resource path for collection resources follow
the convention:

```
/api/3/{resource_name}
```

#### Instances

An instance resource is a "leaf" level resource that may be retrieved, optionally nested within a collection resource.
Instance resources are usually retrievable with opaque identifiers. The resource path for instance resources follows
the convention:

```
/api/3/{resource_name}/{instance_id}...
```

## Verbs

The following HTTP operations are supported throughout this API. The general usage of the operation and both
its failure and success status codes are outlined below.

\| Verb      \| Usage                                                                                 \| Success     \| Failure                                                        \|
\| --------- \| ------------------------------------------------------------------------------------- \| ----------- \| -------------------------------------------------------------- \|
\| `GET`     \| Used to retrieve a resource by identifier, or a collection of resources by type.      \| `200`       \| `400`, `401`, `402`, `404`, `405`, `408`, `410`, `415`, `500`  \|
\| `POST`    \| Creates a resource with an application-specified identifier.                          \| `201`       \| `400`, `401`, `404`, `405`, `408`, `413`, `415`, `500`         \|
\| `POST`    \| Performs a request to queue an asynchronous job.                                      \| `202`       \| `400`, `401`, `405`, `408`, `410`, `413`, `415`, `500`         \|
\| `PUT`     \| Creates a resource with a client-specified identifier.                                \| `200`       \| `400`, `401`, `403`, `405`, `408`, `410`, `413`, `415`, `500`  \|
\| `PUT`     \| Performs a full update of a resource with a specified identifier.                     \| `201`       \| `400`, `401`, `403`, `405`, `408`, `410`, `413`, `415`, `500`  \|
\| `DELETE`  \| Deletes a resource by identifier or an entire collection of resources.                \| `204`       \| `400`, `401`, `405`, `408`, `410`, `413`, `415`, `500`         \|
\| `OPTIONS` \| Requests what operations are available on a resource.                                 \| `200`       \| `401`, `404`, `405`, `408`, `500`                              \|

### Common Operations

#### OPTIONS

All resources respond to the `OPTIONS` request, which allows discoverability of available operations that are supported.
The `OPTIONS` response returns the acceptable HTTP operations on that resource within the `Allow` header. The response
is always a `200 OK` status.

### Collection Resources

Collection resources can support the `GET`, `POST`, `PUT`, and `DELETE` operations.

#### GET

The `GET` operation invoked on a collection resource indicates a request to retrieve all, or some, of the entities
contained within the collection. This also includes the optional capability to filter or search resources during
the request. The response from a collection listing is a paginated document. See
[hypermedia links](#section/Overview/Paging) for more information.

#### POST

The `POST` is a non-idempotent operation that allows for the creation of a new resource when the resource identifier
is not provided by the system during the creation operation (i.e. the Security Console generates the identifier). The
content of the `POST` request is sent in the request body. The response to a successful `POST` request should be a
`201 CREATED` with a valid `Location` header field set to the URI that can be used to access to the newly
created resource.

The `POST` to a collection resource can also be used to interact with asynchronous resources. In this situation,
instead of a `201 CREATED` response, the `202 ACCEPTED` response indicates that processing of the request is not fully
complete but has been accepted for future processing. This request will respond similarly with a `Location` header with
link to the job-oriented asynchronous resource that was created and/or queued.

#### PUT

The `PUT` is an idempotent operation that either performs a create with user-supplied identity, or a full replace
or update of a resource by a known identifier. The response to a `PUT` operation to create an entity is a `201 Created`
with a valid `Location` header field set to the URI that can be used to access to the newly created resource.

`PUT` on a collection resource replaces all values in the collection. The typical response to a `PUT` operation that
updates an entity is hypermedia links, which may link to related resources caused by the side-effects of the changes
performed.

#### DELETE

The `DELETE` is an idempotent operation that physically deletes a resource, or removes an association between resources.
The typical response to a `DELETE` operation is hypermedia links, which may link to related resources caused by the
side-effects of the changes performed.

### Instance Resources

Instance resources can support the `GET`, `PUT`, `POST`, `PATCH` and `DELETE` operations.

#### GET

Retrieves the details of a specific resource by its identifier. The details retrieved can be controlled through
property selection and property views. The content of the resource is returned within the body of the response in the
acceptable media type.

#### PUT

Allows for and idempotent "full update" (complete replacement) on a specific resource. If the resource does not exist,
it will be created; if it does exist, it is completely overwritten. Any omitted properties in the request are assumed to
be undefined/null. For "partial updates" use `POST` or `PATCH` instead.

The content of the `PUT` request is sent in the request body. The identifier of the resource is specified within the URL
(not the request body). The response to a successful `PUT` request is a `201 CREATED` to represent the created status,
with a valid `Location` header field set to the URI that can be used to access to the newly created (or fully replaced)
resource.

#### POST

Performs a non-idempotent creation of a new resource. The `POST` of an instance resource most commonly occurs with the
use of nested resources (e.g. searching on a parent collection resource). The response to a `POST` of an instance
resource is typically a `200 OK` if the resource is non-persistent, and a `201 CREATED` if there is a resource
created/persisted as a result of the operation. This varies by endpoint.

#### PATCH

The `PATCH` operation is used to perform a partial update of a resource. `PATCH` is a non-idempotent operation that
enforces an atomic mutation of a resource. Only the properties specified in the request are to be overwritten on the
resource it is applied to. If a property is missing, it is assumed to not have changed.

#### DELETE

Permanently removes the individual resource from the system. If the resource is an association between resources, only
the association is removed, not the resources themselves. A successful deletion of the resource should return
`204 NO CONTENT` with no response body. This operation is not fully idempotent, as follow-up requests to delete a
non-existent resource should return a `404 NOT FOUND`.

## Requests

Unless otherwise indicated, the default request body media type is `application/json`.

### Headers

Commonly used request headers include:

\| Header             \| Example                                       \| Purpose                                                                                        \|
\| ------------------ \| --------------------------------------------- \| ---------------------------------------------------------------------------------------------- \|
\| `Accept`           \| `application/json`                            \| Defines what acceptable content types are allowed by the client. For all types, use `*/*`.     \|
\| `Accept-Encoding`  \| `deflate, gzip`                               \| Allows for the encoding to be specified (such as gzip).                                        \|
\| `Accept-Language`  \| `en-US`                                       \| Indicates to the server the client's locale (defaults `en-US`).                                \|
\| `Authorization`   \| `Basic Base64("username:password")`           \| Basic authentication                                                                           \|
\| `Token`           \| `123456`                                      \| Two-factor authentication token (if enabled)                                                   \|

### Dates & Times

Dates and/or times are specified as strings in the ISO 8601 format(s). The following formats are supported as input:

\| Value                       \| Format                                                 \| Notes                                                 \|
\| --------------------------- \| ------------------------------------------------------ \| ----------------------------------------------------- \|
\| Date                        \| YYYY-MM-DD                                             \| Defaults to 12 am UTC (if used for a date & time      \|
\| Date & time only            \| YYYY-MM-DD'T'hh:mm:ss[.nnn]                            \| Defaults to UTC                                       \|
\| Date & time in UTC          \| YYYY-MM-DD'T'hh:mm:ss[.nnn]Z                           \|                                                       \|
\| Date & time w/ offset       \| YYYY-MM-DD'T'hh:mm:ss[.nnn][+&#124;-]hh:mm             \|                                                       \|
\| Date & time w/ zone-offset  \| YYYY-MM-DD'T'hh:mm:ss[.nnn][+&#124;-]hh:mm[<zone-id>]  \|                                                       \|

### Timezones

Timezones are specified in the regional zone format, such as `"America/Los_Angeles"`, `"Asia/Tokyo"`, or `"GMT"`.

### Paging

Pagination is supported on certain collection resources using a combination of two query parameters, `page` and `size`.
As these are control parameters, they are prefixed with the underscore character. The page parameter dictates the
zero-based index of the page to retrieve, and the `size` indicates the size of the page.

For example, `/resources?page=2&size=10` will return page 3, with 10 records per page, giving results 21-30.

The maximum page size for a request is 500.

### Sorting

Sorting is supported on paginated resources with the `sort` query parameter(s). The sort query parameter(s) supports
identifying a single or multi-property sort with a single or multi-direction output. The format of the parameter is:

```
sort=property[,ASC\|DESC]...
```

Therefore, the request `/resources?sort=name,title,DESC` would return the results sorted by the name and title
descending, in that order. The sort directions are either ascending `ASC` or descending `DESC`. With single-order
sorting, all properties are sorted in the same direction. To sort the results with varying orders by property,
 multiple sort parameters are passed.

For example, the request `/resources?sort=name,ASC&sort=title,DESC` would sort by name ascending and title
descending, in that order.

## Responses

The following response statuses may be returned by this API.

\| Status \| Meaning                  \| Usage                                                                                                                                                                    \|
\| ------ \| ------------------------ \|------------------------------------------------------------------------------------------------------------------------------------------------------------------------- \|
\| `200`  \| OK                       \| The operation performed without error according to the specification of the request, and no more specific 2xx code is suitable.                                          \|
\| `201`  \| Created                  \| A create request has been fulfilled and a resource has been created. The resource is available as the URI specified in the response, including the `Location` header.    \|
\| `202`  \| Accepted                 \| An asynchronous task has been accepted, but not guaranteed, to be processed in the future.                                                                               \|
\| `400`  \| Bad Request              \| The request was invalid or cannot be otherwise served. The request is not likely to succeed in the future without modifications.                                         \|
\| `401`  \| Unauthorized             \| The user is unauthorized to perform the operation requested, or does not maintain permissions to perform the operation on the resource specified.                        \|
\| `403`  \| Forbidden                \| The resource exists to which the user has access, but the operating requested is not permitted.                                                                          \|
\| `404`  \| Not Found                \| The resource specified could not be located, does not exist, or an unauthenticated client does not have permissions to a resource.                                       \|
\| `405`  \| Method Not Allowed       \| The operations may not be performed on the specific resource. Allowed operations are returned and may be performed on the resource.                                      \|
\| `408`  \| Request Timeout          \| The client has failed to complete a request in a timely manner and the request has been discarded.                                                                       \|
\| `413`  \| Request Entity Too Large \| The request being provided is too large for the server to accept processing.                                                                                             \|
\| `415`  \| Unsupported Media Type   \| The media type is not supported for the requested resource.                                                                                                              \|
\| `500`  \| Internal Server Error    \| An internal and unexpected error has occurred on the server at no fault of the client.                                                                                   \|

### Security

The response statuses 401, 403 and 404 need special consideration for security purposes. As necessary,
error statuses and messages may be obscured to strengthen security and prevent information exposure. The following is a
guideline for privileged resource response statuses:

\| Use Case                                                           \| Access             \| Resource           \| Permission   \| Status       \|
\| ------------------------------------------------------------------ \| ------------------ \|------------------- \| ------------ \| ------------ \|
\| Unauthenticated access to an unauthenticated resource.             \| Unauthenticated    \| Unauthenticated    \| Yes          \| `20x`        \|
\| Unauthenticated access to an authenticated resource.               \| Unauthenticated    \| Authenticated      \| No           \| `401`        \|
\| Unauthenticated access to an authenticated resource.               \| Unauthenticated    \| Non-existent       \| No           \| `401`        \|
\| Authenticated access to a unauthenticated resource.                \| Authenticated      \| Unauthenticated    \| Yes          \| `20x`        \|
\| Authenticated access to an authenticated, unprivileged resource.   \| Authenticated      \| Authenticated      \| No           \| `404`        \|
\| Authenticated access to an authenticated, privileged resource.     \| Authenticated      \| Authenticated      \| Yes          \| `20x`        \|
\| Authenticated access to an authenticated, non-existent resource    \| Authenticated      \| Non-existent       \| Yes          \| `404`        \|

### Headers

Commonly used response headers include:

\| Header                     \|  Example                          \| Purpose                                                         \|
\| -------------------------- \| --------------------------------- \| --------------------------------------------------------------- \|
\| `Allow`                    \| `OPTIONS, GET`                    \| Defines the allowable HTTP operations on a resource.            \|
\| `Cache-Control`            \| `no-store, must-revalidate`       \| Disables caching of resources (as they are all dynamic).        \|
\| `Content-Encoding`         \| `gzip`                            \| The encoding of the response body (if any).                     \|
\| `Location`                 \|                                   \| Refers to the URI of the resource created by a request.         \|
\| `Transfer-Encoding`        \| `chunked`                         \| Specified the encoding used to transform response.              \|
\| `Retry-After`              \| 5000                              \| Indicates the time to wait before retrying a request.           \|
\| `X-Content-Type-Options`   \| `nosniff`                         \| Disables MIME type sniffing.                                    \|
\| `X-XSS-Protection`         \| `1; mode=block`                   \| Enables XSS filter protection.                                  \|
\| `X-Frame-Options`          \| `SAMEORIGIN`                      \| Prevents rendering in a frame from a different origin.          \|
\| `X-UA-Compatible`          \| `IE=edge,chrome=1`                \| Specifies the browser mode to render in.                        \|

### Format

When `application/json` is returned in the response body it is always pretty-printed (indented, human readable output).
Additionally, gzip compression/encoding is supported on all responses.

#### Dates & Times

Dates or times are returned as strings in the ISO 8601 'extended' format. When a date and time is returned (instant) the value is converted to UTC.

For example:

\| Value           \| Format                         \| Example               \|
\| --------------- \| ------------------------------ \| --------------------- \|
\| Date            \| `YYYY-MM-DD`                   \| 2017-12-03            \|
\| Date & Time     \| `YYYY-MM-DD'T'hh:mm:ss[.nnn]Z` \| 2017-12-03T10:15:30Z  \|

#### Content

In some resources a Content data type is used. This allows for multiple formats of representation to be returned
within resource, specifically `"html"` and `"text"`. The `"text"` property returns a flattened representation suitable
for output in textual displays. The `"html"` property returns an HTML fragment suitable for display within an HTML
element. Note, the HTML returned is not a valid stand-alone HTML document.

#### Paging

The response to a paginated request follows the format:

```json
{
   resources": [ 
      ... 
   ],
   "page": { 
      "number" : ...,
      "size" : ...,
      "totalResources" : ...,
      "totalPages" : ...
   },
   "links": [ 
      "first" : {
         "href" : "..."
       },
       "prev" : {
         "href" : "..."
       },
       "self" : {
         "href" : "..."
       },
       "next" : {
         "href" : "..."
       },
       "last" : {
         "href" : "..."
       } 
   ]
}
```

The `resources` property is an array of the resources being retrieved from the endpoint, each which should contain at
minimum a "self" relation hypermedia link. The `page` property outlines the details of the current page and total
possible pages. The object for the page includes the following properties:

- number - The page number (zero-based) of the page returned.
- size - The size of the pages, which is less than or equal to the maximum page size.
- totalResources - The total amount of resources available across all pages.
- totalPages - The total amount of pages.

The last property of the paged response is the `links` array, which contains all available hypermedia links. For
paginated responses, the "self", "next", "previous", "first", and "last" links are returned. The "self" link must
always be returned and should contain a link to allow the client to replicate the original request against the
collection resource in an identical manner to that in which it was invoked.

The "next" and "previous" links are present if either or both there exists a previous or next page, respectively.
The "next" and "previous" links have hrefs that allow "natural movement" to the next page, that is all parameters
required to move the next page are provided in the link. The "first" and "last" links provide references to the first
and last pages respectively.

Requests outside the boundaries of the pageable will result in a `404 NOT FOUND`. Paginated requests do not provide a
"stateful cursor" to the client, nor does it need to provide a read consistent view. Records in adjacent pages may
change while pagination is being traversed, and the total number of pages and resources may change between requests
within the same filtered/queries resource collection.

#### Property Views

The "depth" of the response of a resource can be configured using a "view". All endpoints supports two views that can
tune the extent of the information returned in the resource. The supported views are `summary` and `details` (the default).
View are specified using a query parameter, in this format:

```bash
/<resource>?view={viewName}
```

#### Error

Any error responses can provide a response body with a message to the client indicating more information (if applicable)
to aid debugging of the error. All 40x and 50x responses will return an error response in the body. The format of the
response is as follows:

```json
{
   "status": <statusCode>,
   "message": <message>,
   "links" : [ {
      "rel" : "...",
      "href" : "..."
    } ]
} 
 ```

The `status` property is the same as the HTTP status returned in the response, to ease client parsing. The message
property is a localized message in the request client's locale (if applicable) that articulates the nature of the
error. The last property is the `links` property. This may contain additional
[hypermedia links](#section/Overview/Authentication) to troubleshoot.

#### Search Criteria <a section="section/Responses/SearchCriteria"></a>

Multiple resources make use of search criteria to match assets. Search criteria is an array of search filters. Each
search filter has a generic format of:

```json
{ 
   "field": "<field-name>", 
   "operator": "<operator>", 
   ["value": <value>,]
   ["lower": <value>,]
   ["upper": <value>]
}
   
```

Every filter defines two required properties `field` and `operator`. The field is the name of an asset property that
is being filtered on. The operator is a type and property-specific operating performed on the filtered property. The
valid values for fields and operators are outlined in the table below. Depending on the data type of the operator
the value may be a numeric or string format.

Every filter also defines one or more values that are supplied to the operator. The valid values vary by operator
and are outlined below.

##### Fields

The following table outlines the search criteria fields and the available operators:

\| Field                             \| Operators                                                                                                                      \|
\| --------------------------------- \| ------------------------------------------------------------------------------------------------------------------------------ \|
\| `alternate-address-type`          \| `in`                                                                                                                           \|
\| `container-image`                 \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain` `is-like` `not-like`                                     \|
\| `container-status`                \| `is` `is-not`                                                                                                                  \|
\| `containers`                      \| `are`                                                                                                                          \|
\| `criticality-tag`                 \| `is` `is-not` `is-greater-than` `is-less-than` `is-applied` `is-not-applied`                                                  \|
\| `custom-tag`                      \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain` `is-applied` `is-not-applied`                            \|
\| `cve`                             \| `is` `is-not` `contains` `does-not-contain`                                                                                    \|
\| `cvss-access-complexity`          \| `is` `is-not`                                                                                                                  \|
\| `cvss-authentication-required`    \| `is` `is-not`                                                                                                                  \|
\| `cvss-access-vector`              \| `is` `is-not`                                                                                                                  \|
\| `cvss-availability-impact`        \| `is` `is-not`                                                                                                                  \|
\| `cvss-confidentiality-impact`     \| `is` `is-not`                                                                                                                  \|
\| `cvss-integrity-impact`           \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-confidentiality-impact`  \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-integrity-impact`        \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-availability-impact`     \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-attack-vector`           \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-attack-complexity`       \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-user-interaction`        \| `is` `is-not`                                                                                                                  \|
\| `cvss-v3-privileges-required`     \| `is` `is-not`                                                                                                                  \|
\| `host-name`                       \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain` `is-empty` `is-not-empty` `is-like` `not-like`           \|
\| `host-type`                       \| `in` `not-in`                                                                                                                  \|
\| `ip-address`                      \| `is` `is-not` `in-range` `not-in-range` `is-like` `not-like`                                                                   \|
\| `ip-address-type`                 \| `in` `not-in`                                                                                                                  \|
\| `last-scan-date`                  \| `is-on-or-before` `is-on-or-after` `is-between` `is-earlier-than` `is-within-the-last`                                         \|
\| `location-tag`                    \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain` `is-applied` `is-not-applied`                            \|
\| `mobile-device-last-sync-time`    \| `is-within-the-last` `is-earlier-than`                                                                                         \|
\| `open-ports`                      \| `is` `is-not` `in-range`                                                                                                      \|
\| `operating-system`                \| `contains` `does-not-contain` `is-empty` `is-not-empty`                                                                     \|
\| `owner-tag`                       \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain` `is-applied` `is-not-applied`                            \|
\| `pci-compliance`                  \| `is`                                                                                                                           \|
\| `risk-score`                      \| `is` `is-not` `is-greater-than` `is-less-than` `in-range`                                                                      \|
\| `service-name`                    \| `contains` `does-not-contain`                                                                                                  \|
\| `site-id`                         \| `in` `not-in`                                                                                                                  \|
\| `software`                        \| `contains` `does-not-contain`                                                                                                  \|
\| `vAsset-cluster`                  \| `is` `is-not` `contains` `does-not-contain` `starts-with`                                                                      \|
\| `vAsset-datacenter`               \| `is` `is-not`                                                                                                                  \|
\| `vAsset-host-name`                \| `is` `is-not` `contains` `does-not-contain` `starts-with`                                                                      \|
\| `vAsset-power-state`              \| `in` `not-in`                                                                                                                  \|
\| `vAsset-resource-pool-path`       \| `contains` `does-not-contain`                                                                                                  \|
\| `vulnerability-assessed`          \| `is-on-or-before` `is-on-or-after` `is-between` `is-earlier-than` `is-within-the-last`                                         \|
\| `vulnerability-category`          \| `is` `is-not` `starts-with` `ends-with` `contains` `does-not-contain`                                                          \|
\| `vulnerability-cvss-v3-score`     \| `is` `is-not`                                                                                                                  \|
\| `vulnerability-cvss-score`        \| `is` `is-not` `in-range` `is-greater-than` `is-less-than`                                                                      \|
\| `vulnerability-exposures`         \| `includes` `does-not-include`                                                                                                  \|
\| `vulnerability-title`             \| `contains` `does-not-contain` `is` `is-not` `starts-with` `ends-with`                                                          \|
\| `vulnerability-validated-status`  \| `are`                                                                                                                          \|

##### Enumerated Properties

The following fields have enumerated values:

\| Field                                     \| Acceptable Values                                                                                             \|
\| ----------------------------------------- \| ------------------------------------------------------------------------------------------------------------- \|
\| `alternate-address-type`                  \| 0=IPv4, 1=IPv6                                                                                                \|
\| `containers`                              \| 0=present, 1=not present                                                                                      \|
\| `container-status`                        \| `created` `running` `paused` `restarting` `exited` `dead` `unknown`                                           \|
\| `cvss-access-complexity`                  \| <ul><li><code>L</code> = Low</li><li><code>M</code> = Medium</li><li><code>H</code> = High</li></ul>          \|
\| `cvss-integrity-impact`                   \| <ul><li><code>N</code> = None</li><li><code>P</code> = Partial</li><li><code>C</code> = Complete</li></ul>    \|
\| `cvss-confidentiality-impact`             \| <ul><li><code>N</code> = None</li><li><code>P</code> = Partial</li><li><code>C</code> = Complete</li></ul>    \|
\| `cvss-availability-impact`                \| <ul><li><code>N</code> = None</li><li><code>P</code> = Partial</li><li><code>C</code> = Complete</li></ul>    \|
\| `cvss-access-vector`                      \| <ul><li><code>L</code> = Local</li><li><code>A</code> = Adjacent</li><li><code>N</code> = Network</li></ul>   \|
\| `cvss-authentication-required`            \| <ul><li><code>N</code> = None</li><li><code>S</code> = Single</li><li><code>M</code> = Multiple</li></ul>     \|
\| `cvss-v3-confidentiality-impact`     \| <ul><li><code>L</code> = Local</li><li><code>L</code> = Low</li><li><code>N</code> = None</li><li><code>H</code> = High</li></ul>          \|
\| `cvss-v3-integrity-impact`            \| <ul><li><code>L</code> = Local</li><li><code>L</code> = Low</li><li><code>N</code> = None</li><li><code>H</code> = High</li></ul>          \|
\| `cvss-v3-availability-impact`             \| <ul><li><code>N</code> = None</li><li><code>L</code> = Low</li><li><code>H</code> = High</li></ul>    \|
\| `cvss-v3-attack-vector`                \| <ul><li><code>N</code> = Network</li><li><code>A</code> = Adjacent</li><li><code>L</code> = Local</li><li><code>P</code> = Physical</li></ul>    \|
\| `cvss-v3-attack-complexity`                      \| <ul><li><code>L</code> = Low</li><li><code>H</code> = High</li></ul>   \|
\| `cvss-v3-user-interaction`            \| <ul><li><code>N</code> = None</li><li><code>R</code> = Required</li></ul>     \|
\| `cvss-v3-privileges-required`         \| <ul><li><code>N</code> = None</li><li><code>L</code> = Low</li><li><code>H</code> = High</li></ul>    \|
\| `host-type`                               \| 0=Unknown, 1=Guest, 2=Hypervisor, 3=Physical, 4=Mobile                                                        \|
\| `ip-address-type`                         \| 0=IPv4, 1=IPv6                                                                                                \|
\| `pci-compliance`                          \| 0=fail, 1=pass                                                                                                \|
\| `vulnerability-validated-status`          \| 0=present, 1=not present                                                                                      \|

##### Operator Properties <a section="section/Responses/SearchCriteria/OperatorProperties"></a>

The following table outlines which properties are required for each operator and the appropriate data type(s):

\| Operator              \| `value`               \| `lower`               \| `upper`                \|
\| ----------------------\|-----------------------\|-----------------------\|------------------------\|
\| `are`                 \| `string`              \|                       \|                        \|
\| `contains`            \| `string`              \|                       \|                        \|
\| `does-not-contain`    \| `string`              \|                       \|                        \|
\| `ends with`           \| `string`              \|                       \|                        \|
\| `in`                  \| `Array[ string ]`     \|                       \|                        \|
\| `in-range`            \|                       \| `numeric`             \| `numeric`              \|
\| `includes`            \| `Array[ string ]`     \|                       \|                        \|
\| `is`                  \| `string`              \|                       \|                        \|
\| `is-applied`          \|                       \|                       \|                        \|
\| `is-between`          \|                       \| `string` (yyyy-MM-dd) \| `numeric` (yyyy-MM-dd) \|
\| `is-earlier-than`     \| `numeric` (days)      \|                       \|                        \|
\| `is-empty`            \|                       \|                       \|                        \|
\| `is-greater-than`     \| `numeric`             \|                       \|                        \|
\| `is-on-or-after`      \| `string` (yyyy-MM-dd) \|                       \|                        \|
\| `is-on-or-before`     \| `string` (yyyy-MM-dd) \|                       \|                        \|
\| `is-not`              \| `string`              \|                       \|                        \|
\| `is-not-applied`      \|                       \|                       \|                        \|
\| `is-not-empty`        \|                       \|                       \|                        \|
\| `is-within-the-last`  \| `numeric` (days)      \|                       \|                        \|
\| `less-than`           \| `string`              \|                       \|                        \|
\| `like`                \| `string`              \|                       \|                        \|
\| `not-contains`        \| `string`              \|                       \|                        \|
\| `not-in`              \| `Array[ string ]`     \|                       \|                        \|
\| `not-in-range`        \|                       \| `numeric`             \| `numeric`              \|
\| `not-like`            \| `string`              \|                       \|                        \|
\| `starts-with`         \| `string`              \|                       \|                        \|

#### Discovery Connection Search Criteria <a section="section/Responses/DiscoverySearchCriteria"></a>

Dynamic sites make use of search criteria to match assets from a discovery connection. Search criteria is an array of search filters.  

Each search filter has a generic format of:

```json
{ 
   "field": "<field-name>", 
   "operator": "<operator>", 
   ["value": "<value>",]
   ["lower": "<value>",]
   ["upper": "<value>"]
}
   
```

Every filter defines two required properties `field` and `operator`. The field is the name of an asset property that
is being filtered on. The list of supported fields vary depending on the type of discovery connection configured
for the dynamic site (e.g vSphere, ActiveSync, etc.). The operator is a type and property-specific operating
performed on the filtered property. The valid values for fields outlined in the tables below and are grouped by the
type of connection.  

Every filter also defines one or more values that are supplied to the operator. See
<a href="#section/Responses/SearchCriteria/OperatorProperties">Search Criteria Operator Properties</a> for more
information on the valid values for each operator.  

##### Fields (ActiveSync)

This section documents search criteria information for ActiveSync discovery connections. The discovery connections
must be one of the following types: `"activesync-ldap"`, `"activesync-office365"`, or `"activesync-powershell"`.  

The following table outlines the search criteria fields and the available operators for ActiveSync connections:

\| Field                             \| Operators                                                     \|
\| --------------------------------- \| ------------------------------------------------------------- \|
\| `last-sync-time`                  \| `is-within-the-last` `is-earlier-than`                       \|
\| `operating-system`                \| `contains` `does-not-contain`                                \|
\| `user`                            \| `is` `is-not` `contains` `does-not-contain` `starts-with` \|

##### Fields (AWS)

This section documents search criteria information for AWS discovery connections. The discovery connections must be the type `"aws"`.  

The following table outlines the search criteria fields and the available operators for AWS connections:

\| Field                   \| Operators                                                     \|
\| ----------------------- \| ------------------------------------------------------------- \|
\| `availability-zone`     \| `contains` `does-not-contain`                                \|
\| `guest-os-family`       \| `contains` `does-not-contain`                                \|
\| `instance-id`           \| `contains` `does-not-contain`                                \|
\| `instance-name`         \| `is` `is-not` `contains` `does-not-contain` `starts-with` \|
\| `instance-state`        \| `in` `not-in`                                                \|
\| `instance-type`         \| `in` `not-in`                                                \|
\| `ip-address`            \| `in-range` `not-in-range` `is` `is-not`                    \|
\| `region`                \| `in` `not-in`                                                \|
\| `vpc-id`                \| `is` `is-not` `contains` `does-not-contain` `starts-with` \|

##### Fields (DHCP)

This section documents search criteria information for DHCP discovery connections. The discovery connections must be the type `"dhcp"`.  

The following table outlines the search criteria fields and the available operators for DHCP connections:

\| Field           \| Operators                                                     \|
\| --------------- \| ------------------------------------------------------------- \|
\| `host-name`     \| `is` `is-not` `contains` `does-not-contain` `starts-with` \|
\| `ip-address`    \| `in-range` `not-in-range` `is` `is-not`                    \|
\| `mac-address`   \| `is` `is-not` `contains` `does-not-contain` `starts-with` \|

##### Fields (Sonar)

This section documents search criteria information for Sonar discovery connections. The discovery connections must be the type `"sonar"`.  

The following table outlines the search criteria fields and the available operators for Sonar connections:

\| Field               \| Operators            \|
\| ------------------- \| -------------------- \|
\| `search-domain`     \| `contains` `is`     \|
\| `ip-address`        \| `in-range` `is`     \|
\| `sonar-scan-date`   \| `is-within-the-last` \|

##### Fields (vSphere)

This section documents search criteria information for vSphere discovery connections. The discovery connections must be the type `"vsphere"`.  

The following table outlines the search criteria fields and the available operators for vSphere connections:

\| Field                \| Operators                                                                                  \|
\| -------------------- \| ------------------------------------------------------------------------------------------ \|
\| `cluster`            \| `is` `is-not` `contains` `does-not-contain` `starts-with`                              \|
\| `data-center`        \| `is` `is-not`                                                                             \|
\| `discovered-time`    \| `is-on-or-before` `is-on-or-after` `is-between` `is-earlier-than` `is-within-the-last` \|
\| `guest-os-family`    \| `contains` `does-not-contain`                                                             \|
\| `host-name`          \| `is` `is-not` `contains` `does-not-contain` `starts-with`                              \|
\| `ip-address`         \| `in-range` `not-in-range` `is` `is-not`                                                 \|
\| `power-state`        \| `in` `not-in`                                                                             \|
\| `resource-pool-path` \| `contains` `does-not-contain`                                                             \|
\| `last-time-seen`     \| `is-on-or-before` `is-on-or-after` `is-between` `is-earlier-than` `is-within-the-last` \|
\| `vm`                 \| `is` `is-not` `contains` `does-not-contain` `starts-with`                              \|

##### Enumerated Properties (vSphere)

The following fields have enumerated values:

\| Field         \| Acceptable Values                    \|
\| ------------- \| ------------------------------------ \|
\| `power-state` \| `poweredOn` `poweredOff` `suspended` \|

## HATEOAS

This API follows Hypermedia as the Engine of Application State (HATEOAS) principals and is therefore hypermedia friendly.
Hyperlinks are returned in the `links` property of any given resource and contain a fully-qualified hyperlink to
the corresponding resource. The format of the hypermedia link adheres to both the
<a target="_blank" rel="noopener noreferrer" href="http://jsonapi.org">{json:api} v1</a>
<a target="_blank" rel="noopener noreferrer" href="http://jsonapi.org/format/#document-links">"Link Object"</a> and
<a target="_blank" rel="noopener noreferrer" href="http://json-schema.org/latest/json-schema-hypermedia.html">JSON Hyper-Schema</a>
<a target="_blank" rel="noopener noreferrer" href="http://json-schema.org/latest/json-schema-hypermedia.html#rfc.section.5.2">"Link Description Object"</a>
formats. For example:

```json
"links": [{
  "rel": "<relation>",
  "href": "<href>"
  ...
}]
```

Where appropriate link objects may also contain additional properties than the `rel` and `href` properties, such as `id`, `type`, etc.

See the [Root](#tag/Root) resources for the entry points into API discovery.

## Version: 3

**Contact information:**  
Rapid7  
support@rapid7.com  

### Security
**Basic**  

| basic | *Basic* |
| ----- | ------- |

**Schemes:** https

---
## Root
Provides access to primary entry point for discovering the available resources in this API.

### /api/3

#### GET
##### Summary

Resources

##### Description

Returns a listing of the resources (endpoints) that are available to be invoked in this API.

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

---
## Administration
Provides access administrative operations and procedures.

### /api/3/administration/commands

#### POST
##### Summary

Console Commands

##### Description

Executes a console command against the Security Console. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| command | body | The console command to execute. | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ConsoleCommandOutput](#consolecommandoutput) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/administration/info

#### GET
##### Summary

Information

##### Description

Returns system details, including host and version information.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Info](#info) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/administration/license

#### GET
##### Summary

License

##### Description

Returns the enabled features and limits of the current license. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [License](#license) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

License

##### Description

Licenses the product with an activation key or a provided license file. If both are provided, the license file is preferred. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| license | formData | The contents of a license (.lic) file. | No | file |
| key | query | A license activation key. | No | string |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/administration/properties

#### GET
##### Summary

Properties

##### Description

Returns system details, including host and version information.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [EnvironmentProperties](#environmentproperties) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/administration/settings

#### GET
##### Summary

Settings

##### Description

Returns the current administration settings. <span class="authorization">Global Administrator</span>

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Settings](#settings) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Asset Group
Resources and operations for managing asset groups.

### /api/3/agents

#### GET
##### Summary

Agents

##### Description

Returns the details for all agents.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAgent%C2%BB](#pageof%c2%abagent%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups

#### GET
##### Summary

Asset Groups

##### Description

Returns all asset groups.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| type | query | The type of asset group. | No | string |
| name | query | A search pattern for the name of the asset group. Searches are case-insensitive contains. | No | string |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAssetGroup%C2%BB](#pageof%c2%abassetgroup%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### POST
##### Summary

Asset Groups

##### Description

Creates a new asset group. The `searchCriteria` field can be passed no matter what the type of the asset group is. The asset group `type` changes when the assets are refreshed. Dynamic asset groups constantly refreshed their membership as assets are scanned whereas static asset groups do not change membership automatically.
See the <a href="#section/Responses/SearchCriteria">Search Criteria</a> for more information on using dynamic criteria.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| assetGroup | body | The details of the asset group. | No | [AssetGroup](#assetgroup) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 201 | Created<br> | [CreatedReference%C2%ABAssetGroupID,Link%C2%BB](#createdreference%c2%abassetgroupid,link%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}

#### GET
##### Summary

Asset Group

##### Description

Returns an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [AssetGroup](#assetgroup) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Asset Group

##### Description

Updates the details of an asset group. See the search criteria endpoint (/search_criteria) for more information about building the search criteria and examples.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| assetGroup | body | The details of the asset group. | No | [AssetGroup](#assetgroup) |

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

Asset Group

##### Description

Deletes the asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/assets

#### GET
##### Summary

Asset Group Assets

##### Description

Returns hypermedia links for the assets that belong to an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABAssetID,Link%C2%BB](#referenceswith%c2%abassetid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Asset Group Assets

##### Description

Updates all the assets that belong to a static asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| assets | body | The assets to place in the asset group.  | No | [ long ] |

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

Asset Group Assets

##### Description

Removes the assets from the given static asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/assets/{assetId}

#### PUT
##### Summary

Asset Group Asset

##### Description

Adds an asset to a static asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
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

Asset Group Asset

##### Description

Removes an asset from an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| assetId | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/search_criteria

#### GET
##### Summary

Asset Group Search Criteria

##### Description

Returns the search criteria of a dynamic asset group.For a reference of valid search criteria input see the <a href="#operation/getAssetsSearchUsingPOST">Asset Search</a> resource.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

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

Asset Group Search Criteria

##### Description

Updates the search criteria of a dynamic asset group. For a reference of valid search criteria input see the <a href="#operation/getAssetsSearchUsingPOST">Asset Search</a> resource.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| criteria | body | The search criteria specification. | No | [SearchCriteria](#searchcriteria) |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/tags

#### GET
##### Summary

Asset Group Tags

##### Description

Returns the tags assigned to an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABTagID,Link%C2%BB](#referenceswith%c2%abtagid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Asset Group Tags

##### Description

Updates the tags of an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| tags | body | The tags to associate to the asset group. | No | [ integer ] |

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

Asset Group Tags

##### Description

Removes all tag associations from the asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/tags/{tagId}

#### PUT
##### Summary

Resources and operations for managing asset groups.

##### Description

Adds a tag to an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| tagId | path | The identifier of the tag. | Yes | integer |

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

Resources and operations for managing asset groups.

##### Description

Removes a tag from an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| tagId | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/users

#### GET
##### Summary

Asset Group Users

##### Description

Returns hypermedia links for the users with access to this asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABUserID,Link%C2%BB](#referenceswith%c2%abuserid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### PUT
##### Summary

Asset Group Users

##### Description

Grants users with sufficient privileges access to an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| users | body | The users to grant access to the asset group. | No | [ integer ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/asset_groups/{id}/users/{userId}

#### PUT
##### Summary

Asset Group User

##### Description

Grants a user with sufficient privileges access to the asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| userId | path | The identifier of the user. | Yes | integer |

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

Asset Group User

##### Description

Removes a user's access from an asset group.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset group. | Yes | integer |
| userId | path | The identifier of the user. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
## Asset
Resources and operations for managing assets. Assets can be created under the <a href="#operation/createAssetUsingPOST">Site Assets</a> resource.

### /api/3/assets

#### GET
##### Summary

Assets

##### Description

Returns all assets for which you have access.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
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

### /api/3/assets/search

#### POST
##### Summary

Asset Search

##### Description

Returns all assets for which you have access that match the given search criteria.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| param1 | body | param1 | Yes | [SearchCriteria](#searchcriteria) |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABAsset%C2%BB](#pageof%c2%abasset%c2%bb) |
| 400 | Bad Request<br> | [BadRequestError](#badrequesterror) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}

#### GET
##### Summary

Asset

##### Description

Returns the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Asset](#asset) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

#### DELETE
##### Summary

Asset

##### Description

Deletes the specified asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/databases

#### GET
##### Summary

Asset Databases

##### Description

Returns the databases enumerated on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABDatabase%C2%BB](#resources%c2%abdatabase%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/files

#### GET
##### Summary

Asset Files

##### Description

Returns the files discovered on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABFile%C2%BB](#resources%c2%abfile%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services

#### GET
##### Summary

Asset Services

##### Description

Returns the services discovered on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABReferenceWithEndpointIDLink,ServiceLink%C2%BB](#referenceswith%c2%abreferencewithendpointidlink,servicelink%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}

#### GET
##### Summary

Asset Service

##### Description

Returns the service running a port and protocol on the asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Service](#service) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/configurations

#### GET
##### Summary

Asset Service Configurations

##### Description

Returns the configuration (properties) of a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABConfiguration%C2%BB](#resources%c2%abconfiguration%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/databases

#### GET
##### Summary

Asset Service Databases

##### Description

Returns the databases running on a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABDatabase%C2%BB](#resources%c2%abdatabase%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/user_groups

#### GET
##### Summary

Asset Service User Groups

##### Description

Returns the user groups enumerated on a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABGroupAccount%C2%BB](#resources%c2%abgroupaccount%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/users

#### GET
##### Summary

Asset Service Users

##### Description

Returns the users enumerated on a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABUserAccount%C2%BB](#resources%c2%abuseraccount%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/web_applications

#### GET
##### Summary

Asset Service Web Applications

##### Description

Returns the web applications running on a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [ReferencesWith%C2%ABWebApplicationID,Link%C2%BB](#referenceswith%c2%abwebapplicationid,link%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/services/{protocol}/{port}/web_applications/{webApplicationId}

#### GET
##### Summary

Asset Service Web Application

##### Description

Returns a web application running on a port and protocol on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| protocol | path | The protocol of the service. | Yes | string |
| port | path | The port of the service. | Yes | integer |
| webApplicationId | path | The identifier of the web application. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [WebApplication](#webapplication) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/software

#### GET
##### Summary

Asset Software

##### Description

Returns the software on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABSoftware%C2%BB](#resources%c2%absoftware%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/tags

#### GET
##### Summary

Asset Tags

##### Description

Returns tags assigned to an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABAssetTag%C2%BB](#resources%c2%abassettag%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/tags/{tagId}

#### PUT
##### Summary

Asset Tag

##### Description

Assigns the specified tag to the asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| tagId | path | The identifier of the tag. | Yes | integer |

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

Asset Tag

##### Description

Removes the specified tag from the asset's tags.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |
| tagId | path | The identifier of the tag. | Yes | integer |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Links](#links) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/user_groups

#### GET
##### Summary

Asset User Groups

##### Description

Returns user groups enumerated on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABGroupAccount%C2%BB](#resources%c2%abgroupaccount%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/assets/{id}/users

#### GET
##### Summary

Asset Users

##### Description

Returns users enumerated on an asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the asset. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Resources%C2%ABUserAccount%C2%BB](#resources%c2%abuseraccount%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/operating_systems

#### GET
##### Summary

Operating Systems

##### Description

Returns all operating systems discovered across all assets.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABOperatingSystem%C2%BB](#pageof%c2%aboperatingsystem%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/operating_systems/{id}

#### GET
##### Summary

Operating System

##### Description

Returns the details for an operating system.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the operating system. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [OperatingSystem](#operatingsystem) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/software

#### GET
##### Summary

Software

##### Description

Returns all software enumerated on any asset.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| page | query | The index of the page (zero-based) to retrieve. | No | integer |
| size | query | The number of records per page to retrieve. | No | integer |
| sort | query | The criteria to sort the records by, in the format: `property[,ASC\|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | No | [ string ] |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [PageOf%C2%ABSoftware%C2%BB](#pageof%c2%absoftware%c2%bb) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

### /api/3/software/{id}

#### GET
##### Summary

Software

##### Description

Returns the details for software.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ------ |
| id | path | The identifier of the software. | Yes | long |

##### Responses

| Code | Description | Schema |
| ---- | ----------- | ------ |
| 200 | OK<br> | [Software](#software) |
| 401 | Unauthorized<br> | [UnauthorizedError](#unauthorizederror) |
| 404 | Not Found<br> | [NotFoundError](#notfounderror) |
| 500 | Internal Server Error<br> | [InternalServerError](#internalservererror) |
| 503 | Service Unavailable<br> | [ServiceUnavailableError](#serviceunavailableerror) |

---
