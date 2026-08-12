# ListKeyResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**created_at** | **str** |  | 
**expires_at** | **str** |  | [optional] 
**key_id** | **str** |  | 
**label** | **str** |  | 
**public_key_pem** | **str** |  | [optional] 

## Example

```python
from s4_client.models.list_key_response import ListKeyResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ListKeyResponse from a JSON string
list_key_response_instance = ListKeyResponse.from_json(json)
# print the JSON string representation of the object
print(ListKeyResponse.to_json())

# convert the object into a dict
list_key_response_dict = list_key_response_instance.to_dict()
# create an instance of ListKeyResponse from a dict
list_key_response_from_dict = ListKeyResponse.from_dict(list_key_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


