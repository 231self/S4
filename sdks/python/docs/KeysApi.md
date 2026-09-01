# maskura_client.KeysApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_key**](KeysApi.md#create_key) | **POST** /dashboard/api/keys | Create a new API key
[**delete_key**](KeysApi.md#delete_key) | **DELETE** /dashboard/api/keys | Revoke an API key
[**get_keys**](KeysApi.md#get_keys) | **GET** /dashboard/api/keys | List API keys for the authenticated user


# **create_key**
> ApiKeyResponse create_key(create_key_request)

Create a new API key

### Example


```python
import maskura_client
from maskura_client.models.api_key_response import ApiKeyResponse
from maskura_client.models.create_key_request import CreateKeyRequest
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.KeysApi(api_client)
    create_key_request = maskura_client.CreateKeyRequest() # CreateKeyRequest | 

    try:
        # Create a new API key
        api_response = api_instance.create_key(create_key_request)
        print("The response of KeysApi->create_key:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling KeysApi->create_key: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **create_key_request** | [**CreateKeyRequest**](CreateKeyRequest.md)|  | 

### Return type

[**ApiKeyResponse**](ApiKeyResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Created key with secret |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_key**
> delete_key(delete_key_request)

Revoke an API key

### Example


```python
import maskura_client
from maskura_client.models.delete_key_request import DeleteKeyRequest
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.KeysApi(api_client)
    delete_key_request = maskura_client.DeleteKeyRequest() # DeleteKeyRequest | 

    try:
        # Revoke an API key
        api_instance.delete_key(delete_key_request)
    except Exception as e:
        print("Exception when calling KeysApi->delete_key: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **delete_key_request** | [**DeleteKeyRequest**](DeleteKeyRequest.md)|  | 

### Return type

void (empty response body)

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_keys**
> List[ListKeyResponse] get_keys()

List API keys for the authenticated user

### Example


```python
import maskura_client
from maskura_client.models.list_key_response import ListKeyResponse
from maskura_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = maskura_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with maskura_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = maskura_client.KeysApi(api_client)

    try:
        # List API keys for the authenticated user
        api_response = api_instance.get_keys()
        print("The response of KeysApi->get_keys:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling KeysApi->get_keys: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[ListKeyResponse]**](ListKeyResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | API keys |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

