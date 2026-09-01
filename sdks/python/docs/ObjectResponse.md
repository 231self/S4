# ObjectResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**key** | **str** |  | 
**size** | **int** |  | 

## Example

```python
from maskura_client.models.object_response import ObjectResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ObjectResponse from a JSON string
object_response_instance = ObjectResponse.from_json(json)
# print the JSON string representation of the object
print(ObjectResponse.to_json())

# convert the object into a dict
object_response_dict = object_response_instance.to_dict()
# create an instance of ObjectResponse from a dict
object_response_from_dict = ObjectResponse.from_dict(object_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


