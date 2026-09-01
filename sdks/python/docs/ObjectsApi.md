# maskura_client.ObjectsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**list_objects**](ObjectsApi.md#list_objects) | **GET** /dashboard/api/objects | List all objects in the store


# **list_objects**
> List[ObjectResponse] list_objects()

List all objects in the store

### Example


```python
import maskura_client
from maskura_client.models.object_response import ObjectResponse
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
    api_instance = maskura_client.ObjectsApi(api_client)

    try:
        # List all objects in the store
        api_response = api_instance.list_objects()
        print("The response of ObjectsApi->list_objects:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ObjectsApi->list_objects: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[ObjectResponse]**](ObjectResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Objects |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

