# DeleteKeyRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**key_id** | **str** |  | 

## Example

```python
from s4_client.models.delete_key_request import DeleteKeyRequest

# TODO update the JSON string below
json = "{}"
# create an instance of DeleteKeyRequest from a JSON string
delete_key_request_instance = DeleteKeyRequest.from_json(json)
# print the JSON string representation of the object
print(DeleteKeyRequest.to_json())

# convert the object into a dict
delete_key_request_dict = delete_key_request_instance.to_dict()
# create an instance of DeleteKeyRequest from a dict
delete_key_request_from_dict = DeleteKeyRequest.from_dict(delete_key_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


