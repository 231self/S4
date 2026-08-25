# .BackendApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getBackend**](BackendApi.md#getBackend) | **GET** /dashboard/api/backend | 
[**putBackend**](BackendApi.md#putBackend) | **PUT** /dashboard/api/backend | 


# **getBackend**
> BackendConfigResponse getBackend()


### Example


```typescript
import { createConfiguration, BackendApi } from 's4-client';

const configuration = createConfiguration();
const apiInstance = new BackendApi(configuration);

const request = {};

const data = await apiInstance.getBackend(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters
This endpoint does not need any parameter.


### Return type

**BackendConfigResponse**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Redacted workspace backend configuration |  -  |
**401** | Not authenticated |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **putBackend**
> BackendConfigResponse putBackend(backendConfigRequest)


### Example


```typescript
import { createConfiguration, BackendApi } from 's4-client';
import type { BackendApiPutBackendRequest } from 's4-client';

const configuration = createConfiguration();
const apiInstance = new BackendApi(configuration);

const request: BackendApiPutBackendRequest = {
  
  backendConfigRequest: {
    accessKey: "accessKey_example",
    backendType: "s3_compatible",
    endpoint: "endpoint_example",
    region: "region_example",
    roleArn: "roleArn_example",
    secretKey: "secretKey_example",
  },
};

const data = await apiInstance.putBackend(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **backendConfigRequest** | **BackendConfigRequest**|  |


### Return type

**BackendConfigResponse**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Redacted saved workspace backend configuration |  -  |
**400** | Incomplete or unsupported configuration |  -  |
**401** | A real authenticated user is required |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)


