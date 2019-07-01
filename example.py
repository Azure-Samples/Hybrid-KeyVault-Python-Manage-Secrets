"""Create a Keyvault in a resource group.
Set a secret inside the keyvault.
Retrieve the secret from the keyvault.
List all the keyvaults in the resource group.
Delete keyvault and resource group.

This script expects that the following environment vars are set:

AZURE_TENANT_ID: your Azure Active Directory tenant id or domain
AZURE_OBJECT_ID: The object ID of the User or Application for access policies. Find this number in the portal
AZURE_CLIENT_ID: your Azure Active Directory Application Client ID
AZURE_CLIENT_SECRET: your Azure Active Directory Application Secret
AZURE_SUBSCRIPTION_ID: your Azure Subscription Id
AZURE_RESOURCE_LOCATION: your resource location
ARM_ENDPOINT: your cloud's resource manager endpoint
"""
import json
import logging
import os
import random

from azure.common.credentials import ServicePrincipalCredentials
from azure.keyvault import KeyVaultAuthentication, KeyVaultClient, KeyVaultId
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.profiles import KnownProfiles
from haikunator import Haikunator
from msrestazure.azure_cloud import get_cloud_from_metadata_endpoint

haikunator = Haikunator()

# Azure Data center
LOCATION = os.environ['AZURE_RESOURCE_LOCATION']

# Resource Group
post_fix = random.randint(100, 500)
GROUP_NAME = 'azure-sample-group-resources-{}'.format(post_fix)

# Keyvault
KV_NAME = haikunator.haikunate()


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


def run_example():
    """Keyvault management example."""
    #
    # Create the Resource Manager Client with an Application (service principal) token provider
    #
    # By Default, use AzureStack supported profile
    KnownProfiles.default.use(KnownProfiles.v2018_03_01_hybrid)

    credentials, subscription_id, mystack_cloud = get_credentials()
    kv_dp_credentials, sub_id, mystack = get_credentials()
    kv_client = KeyVaultManagementClient(credentials, subscription_id,
                                         base_url=mystack_cloud.endpoints.resource_manager)
    resource_client = ResourceManagementClient(credentials, subscription_id,
                                               base_url=mystack_cloud.endpoints.resource_manager)
    kv_data_client = KeyVaultClient(kv_dp_credentials)

    # You MIGHT need to add KeyVault as a valid provider for these credentials
    # If so, this operation has to be done only once for each credentials
    resource_client.providers.register('Microsoft.KeyVault')

    # Create Resource group
    print('Create Resource Group')
    resource_group_params = {'location': LOCATION}
    print_item(resource_client.resource_groups.create_or_update(
        GROUP_NAME, resource_group_params))

    # Create a vault
    print('\nCreate a vault')
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

    # set and get a secret from the vault to validate the client is authenticated
    print('creating secret...')
    secret_bundle = kv_data_client.set_secret(
        vault.properties.vault_uri, 'auth-sample-secret', 'client is authenticated to the vault')
    print(secret_bundle)

    print('getting secret...')
    secret_bundle = kv_data_client.get_secret(
        vault.properties.vault_uri, 'auth-sample-secret', secret_version=KeyVaultId.version_none)
    print(secret_bundle)

    # List the Key vaults
    print('\nList KeyVaults')
    for vault in kv_client.vaults.list():
        print_item(vault)

    # Delete keyvault
    print('\nDelete Keyvault')
    kv_client.vaults.delete(GROUP_NAME, KV_NAME)

    # Delete Resource group and everything in it
    print('\nDelete Resource Group')
    delete_async_operation = resource_client.resource_groups.delete(GROUP_NAME)
    delete_async_operation.wait()
    print("\nDeleted: {}".format(GROUP_NAME))


def print_item(group):
    """Print an instance."""
    print("\tName: {}".format(group.name))
    print("\tId: {}".format(group.id))
    print("\tLocation: {}".format(group.location))
    print("\tTags: {}".format(group.tags))


if __name__ == "__main__":
    run_example()
