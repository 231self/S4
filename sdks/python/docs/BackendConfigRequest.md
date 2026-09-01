# BackendConfigRequest

Dashboard request DTO. Secrets are accepted only on writes and are never reused as a response type. JSON uses `backend_type`: `managed` needs no other fields; `s3_compatible` needs `endpoint`, `access_key`, `secret_key`, and `region`.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**access_key** | **str** |  | [optional] 
**backend_type** | [**BackendType**](BackendType.md) |  | 
**endpoint** | **str** |  | [optional] 
**region** | **str** |  | [optional] 
**role_arn** | **str** |  | [optional] 
**secret_key** | **str** |  | [optional] 

## Example

```python
from maskura_client.models.backend_config_request import BackendConfigRequest

# TODO update the JSON string below
json = "{}"
# create an instance of BackendConfigRequest from a JSON string
backend_config_request_instance = BackendConfigRequest.from_json(json)
# print the JSON string representation of the object
print(BackendConfigRequest.to_json())

# convert the object into a dict
backend_config_request_dict = backend_config_request_instance.to_dict()
# create an instance of BackendConfigRequest from a dict
backend_config_request_from_dict = BackendConfigRequest.from_dict(backend_config_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


