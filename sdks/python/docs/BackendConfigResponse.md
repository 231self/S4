# BackendConfigResponse

Redacted dashboard representation. Credential material is intentionally absent from this type, so a GET cannot serialize it by mistake. Its exact JSON keys are `configured`, `backend_type`, `endpoint`, `region`, `role_arn`, `access_key_configured`, and `secret_key_configured`.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**access_key_configured** | **bool** |  | 
**backend_type** | [**BackendType**](BackendType.md) |  | [optional] 
**configured** | **bool** |  | 
**endpoint** | **str** |  | [optional] 
**region** | **str** |  | [optional] 
**role_arn** | **str** |  | [optional] 
**secret_key_configured** | **bool** |  | 

## Example

```python
from maskura_client.models.backend_config_response import BackendConfigResponse

# TODO update the JSON string below
json = "{}"
# create an instance of BackendConfigResponse from a JSON string
backend_config_response_instance = BackendConfigResponse.from_json(json)
# print the JSON string representation of the object
print(BackendConfigResponse.to_json())

# convert the object into a dict
backend_config_response_dict = backend_config_response_instance.to_dict()
# create an instance of BackendConfigResponse from a dict
backend_config_response_from_dict = BackendConfigResponse.from_dict(backend_config_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


