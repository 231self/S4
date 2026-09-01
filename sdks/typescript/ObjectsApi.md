# .ObjectsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**listObjects**](ObjectsApi.md#listObjects) | **GET** /dashboard/api/objects | List all objects in the store


# **listObjects**
> Array<ObjectResponse> listObjects()


### Example


```typescript
import { createConfiguration, ObjectsApi } from '';

const configuration = createConfiguration();
const apiInstance = new ObjectsApi(configuration);

const request = {};

const data = await apiInstance.listObjects(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters
This endpoint does not need any parameter.


### Return type

**Array<ObjectResponse>**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Objects |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)


