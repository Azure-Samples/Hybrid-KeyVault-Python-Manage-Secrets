---
services: Azure-Stack
platforms: python
author: viananth
---

# Hybrid-KeyVault-Python-Manage-Secrets

This sample demonstrates how to manage key vaults and secrets in AzureStack using the Python SDK.

**On this page**

- [Run this sample](#run)
- [What does example.py do?](#example)
    - [Create a key vault](#create)
    - [Create a secret inside the keyvault](#createsecret)
    - [Get the secret from keyvault](#getsecret)
    - [List keyvaults](#list)
    - [Delete a key vault](#delete)

<a id="run"></a>
## Run this sample

1. If you don't already have it, [install Python](https://www.python.org/downloads/).

2. We recommend using a [virtual environment](https://docs.python.org/3/tutorial/venv.html) to run this example, but it's not mandatory. You can initialize a virtual environment this way:

    ```
    pip install virtualenv
    virtualenv mytestenv
    cd mytestenv
    source bin/activate
    ```

3. Clone the repository.

    ```
    git clone https://github.com/Azure-Samples/Hybrid-KeyVault-Python-Manage-Secrets.git
    ```

4. Install the dependencies using pip.

    ```
    cd Hybrid-KeyVault-Python-Manage-Secrets
    pip install -r requirements.txt
    ```

5. Create a [service principal](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals) to work against AzureStack. Make sure your service principal has [contributor/owner role](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals#assign-role-to-service-principal) on your subscription.

6. Export these environment variables into your current shell. 

    ```
    export AZURE_RESOURCE_LOCATION={your resource location}
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your client id}
    export AZURE_OBJECT_ID={your client's object id}
    export AZURE_CLIENT_SECRET={your client secret}
    export AZURE_SUBSCRIPTION_ID={your subscription id}
    export ARM_ENDPOINT={your AzureStack Resource Manager Endpoint}
    ```

7. Run the sample.

    ```
    python example.py
    ```

<a id="example"></a>
## What is example.py doing?

This sample starts by setting up `ResourceManagementClient` and `KeyVaultManagementClient` objects using your subscription and credentials.

```python
# Get_Credentials function to get credentials object
def get_credentials():
    mystack_cloud = get_cloud_from_metadata_endpoint(
        os.environ['ARM_ENDPOINT'])
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID'],
        cloud_environment=mystack_cloud
    )
    return credentials, subscription_id, mystack_cloud

#
# Create the Resource Manager Client with an Application (service principal) token provider
#
    credentials, subscription_id, mystack_cloud = get_credentials()
    kv_client = KeyVaultManagementClient(credentials, subscription_id,
        base_url=mystack_cloud.endpoints.resource_manager)
    resource_client = ResourceManagementClient(credentials, subscription_id,
        base_url=mystack_cloud.endpoints.resource_manager)

# Credentials for data_plane keyvault client
    kv_dp_credentials, sub_id, mystack = get_credentials()
    kv_data_client = KeyVaultClient(kv_dp_credentials)
```

It registers the subscription for the "Microsoft.KeyVault" namespace
and creates a resource group and a storage account where the media services will be managed.

```python
# You MIGHT need to add KeyVault as a valid provider for these credentials
# If so, this operation has to be done only once for each credentials
resource_client.providers.register('Microsoft.KeyVault')

# Create Resource group
print('Create Resource Group')
    resource_group_params = {'location': LOCATION}
    print_item(resource_client.resource_groups.create_or_update(GROUP_NAME, resource_group_params))
```

Here, the `create_or_update` method returns a `ResourceGroup` object
after performing the appropriate operation,
and the supporting function `print_item` prints some of its attributes.

<a id="create"></a>
### Create a key vault

```python
    vault = kv_client.vaults.create_or_update(
        GROUP_NAME,
        KV_NAME,
        {
            'location': LOCATION,
            'properties': {
                'sku': {
                    'name': 'standard'
                },
                'tenant_id': os.environ['AZURE_TENANT_ID'],
                'access_policies': [{
                    'tenant_id': os.environ['AZURE_TENANT_ID'],
                    'object_id': os.environ['AZURE_OBJECT_ID'],
                    'permissions': {
                        'keys': ['all'],
                        'secrets': ['all']
                    }
                }]
            }
        }
    )
    print_item(vault)
```
The object ID is unique for a User or an Application. Find this number in the Azure Active Directory blade of the Azure portal:
* To find a User's object ID, navigate to "Users and groups" > "All users", search for the user name, and click it.
* To find an Application's object ID, search for the application name under "App registrations" and click it.

In either of these cases, you can then find the object ID in the Essentials box.


<a id="createsecret"></a>
### Create a secret inside the keyvault
```python
secret_bundle = kv_data_client.set_secret(
        vault.properties.vault_uri, 'auth-sample-secret', 'client is authenticated to the vault')
    print(secret_bundle)
```

<a id="getsecret"></a>
### Get secret from keyvault
```python
secret_bundle = kv_data_client.get_secret(
        vault.properties.vault_uri, 'auth-sample-secret', secret_version=KeyVaultId.version_none)
    print(secret_bundle)
```

<a id="list"></a>
### List key vaults

This code lists some attributes of all available key vaults.

```python
for vault in kv_client.vaults.list():
    print_item(vault)
```

<a id="delete"></a>
### Delete a key vault

```python
delete_async_operation = resource_client.resource_groups.delete(GROUP_NAME)
delete_async_operation.wait()
print("\nDeleted: {}".format(GROUP_NAME))
```

Deleting a resource is an asynchronous operation which may take some time, so the object
returned from `delete` represents an operation in progress. Calling `wait` on it
forces the caller to wait until it finishes.
