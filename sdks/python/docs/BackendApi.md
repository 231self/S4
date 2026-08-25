# s4_client.BackendApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_backend**](BackendApi.md#get_backend) | **GET** /dashboard/api/backend | 
[**put_backend**](BackendApi.md#put_backend) | **PUT** /dashboard/api/backend | 


# **get_backend**
> BackendConfigResponse get_backend()

### Example


```python
import s4_client
from s4_client.models.backend_config_response import BackendConfigResponse
from s4_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = s4_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with s4_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = s4_client.BackendApi(api_client)

    try:
        api_response = api_instance.get_backend()
        print("The response of BackendApi->get_backend:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling BackendApi->get_backend: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**BackendConfigResponse**](BackendConfigResponse.md)

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **put_backend**
> BackendConfigResponse put_backend(backend_config_request)

### Example


```python
import s4_client
from s4_client.models.backend_config_request import BackendConfigRequest
from s4_client.models.backend_config_response import BackendConfigResponse
from s4_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = s4_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with s4_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = s4_client.BackendApi(api_client)
    backend_config_request = s4_client.BackendConfigRequest() # BackendConfigRequest | 

    try:
        api_response = api_instance.put_backend(backend_config_request)
        print("The response of BackendApi->put_backend:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling BackendApi->put_backend: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **backend_config_request** | [**BackendConfigRequest**](BackendConfigRequest.md)|  | 

### Return type

[**BackendConfigResponse**](BackendConfigResponse.md)

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

