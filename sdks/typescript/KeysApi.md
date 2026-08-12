# .KeysApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createKey**](KeysApi.md#createKey) | **POST** /dashboard/api/keys | Create a new API key
[**deleteKey**](KeysApi.md#deleteKey) | **DELETE** /dashboard/api/keys | Revoke an API key
[**getKeys**](KeysApi.md#getKeys) | **GET** /dashboard/api/keys | List API keys for the authenticated user


# **createKey**
> ApiKeyResponse createKey(createKeyRequest)


### Example


```typescript
import { createConfiguration, KeysApi } from 's4-client';
import type { KeysApiCreateKeyRequest } from 's4-client';

const configuration = createConfiguration();
const apiInstance = new KeysApi(configuration);

const request: KeysApiCreateKeyRequest = {
  
  createKeyRequest: {
    expiresIn: 0,
    label: "label_example",
    publicKeyPem: "publicKeyPem_example",
  },
};

const data = await apiInstance.createKey(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **createKeyRequest** | **CreateKeyRequest**|  |


### Return type

**ApiKeyResponse**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Created key with secret |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **deleteKey**
> void deleteKey(deleteKeyRequest)


### Example


```typescript
import { createConfiguration, KeysApi } from 's4-client';
import type { KeysApiDeleteKeyRequest } from 's4-client';

const configuration = createConfiguration();
const apiInstance = new KeysApi(configuration);

const request: KeysApiDeleteKeyRequest = {
  
  deleteKeyRequest: {
    keyId: "keyId_example",
  },
};

const data = await apiInstance.deleteKey(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deleteKeyRequest** | **DeleteKeyRequest**|  |


### Return type

**void**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**204** | Key revoked |  -  |
**404** | Key not found |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)

# **getKeys**
> Array<ListKeyResponse> getKeys()


### Example


```typescript
import { createConfiguration, KeysApi } from 's4-client';

const configuration = createConfiguration();
const apiInstance = new KeysApi(configuration);

const request = {};

const data = await apiInstance.getKeys(request);
console.log('API called successfully. Returned data:', data);
```


### Parameters
This endpoint does not need any parameter.


### Return type

**Array<ListKeyResponse>**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | API keys |  -  |

[[Back to top]](#) [[Back to API list]](README.md#documentation-for-api-endpoints) [[Back to Model list]](README.md#documentation-for-models) [[Back to README]](README.md)


