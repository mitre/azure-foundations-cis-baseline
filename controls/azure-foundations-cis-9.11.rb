control 'azure-foundations-cis-9.11' do
  title 'Ensure Azure Key Vaults are Used to Store Secrets'
  desc "Azure Key Vault will store multiple types of sensitive information such as encryption keys, certificate thumbprints, and Managed Identity Credentials. Access to these 'Secrets' can be controlled through granular permissions."

  desc 'rationale',
       'The credentials given to an application have permissions to create, delete, or modify data stored within the systems they access. If these credentials are stored within the application itself, anyone with access to the application or a copy of the code has access to them. Storing within Azure Key Vault as secrets increases security by controlling access. This also allows for updates of the credentials without redeploying the entire application.'

  desc 'impact',
       'Integrating references to secrets within the key vault are required to be specifically integrated within the application code. This will require additional configuration to be made during the writing of an application, or refactoring of an already written one. There are also additional costs that are charged per 10000 requests to the Key Vault.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal
            2. In the expandable menu on the left go to Key Vaults
            3. View the Key Vaults listed.
        Audit from Azure CLI
            To list key vaults within a subscription run the following command:
                Get-AzKeyVault
            To list the secrets within these key vaults run the following command:
                Get-AzKeyVaultSecret [-VaultName] <vault name>
        Audit From Powershell
            To list key vaults within a subscription run the following command:
                Get-AzKeyVault
            To list all secrets in a key vault run the following command:
                Get-AzKeyVaultSecret -VaultName '<vaultName>'"

  desc 'fix',
       %(
        Remediation has 2 steps
                1. Setup the Key Vault
                2. Setup the App Service to use the Key Vault
            Step 1: Set up the Key Vault
                Remediate from Azure CLI
                    az keyvault create --name "<name>" --resource-group "<myResourceGroup>" --location myLocation
                Remediate From Powershell
                    New-AzKeyvault -name <name> -ResourceGroupName <myResourceGroup> -Location <myLocation>
            Step 2: Set up the App Service to use the Key Vault Sample JSON Template for App Service Configuration:
                { //... "resources": [
                        {
                            "type": "Microsoft.Storage/storageAccounts",
                            "name": "[variables('storageAccountName')]",
                            //...
                        },
                        {
                            "type": "Microsoft.Insights/components",
                            "name": "[variables('appInsightsName')]",
                            //...
                        },
                        {
                            "type": "Microsoft.Web/sites",
                            "name": "[variables('functionAppName')]",
                            "identity": {
                                "type": "SystemAssigned"
                            },
                            //...
                            "resources": [
                                {
                                    "type": "config",
                                    "name": "appsettings",
                                    //...
                                    "dependsOn": [
                                        "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]",
                                        "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                        "[resourceId('Microsoft.KeyVault/vaults/secrets', variables('keyVaultName'), variables('storageConnectionStringName'))]",
                                        "[resourceId('Microsoft.KeyVault/vaults/secrets', variables('keyVaultName'), variables('appInsightsKeyName'))]"
                                    ],
                                    "properties": {
                                        "AzureWebJobsStorage": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('storageConnectionStringResourceId')).secretUriWithVersion, ')')]",
                                        "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('storageConnectionStringResourceId')).secretUriWithVersion, ')')]",
                                        "APPINSIGHTS_INSTRUMENTATIONKEY": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('appInsightsKeyResourceId')).secretUriWithVersion, ')')]",
                                        "WEBSITE_ENABLE_SYNC_UPDATE_SITE": "true"
                                        //...
                                    }
                                },
                                {
                                    "type": "sourcecontrols",
                                    "name": "web",
                                    //...
                                    "dependsOn": [
                                        "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]",
                                        "[resourceId('Microsoft.Web/sites/config', variables('functionAppName'), 'appsettings')]"
                                    ]
                                }
                            ]
                        },
                        {
                            "type": "Microsoft.KeyVault/vaults",
                            "name": "[variables('keyVaultName')]",
                            //...
                            "dependsOn": [
                                "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]"
                            ],
                            "properties": {
                                //...
                                "accessPolicies": [
                                    {
                                        "tenantId": "[reference(concat('Microsoft.Web/sites/', variables('functionAppName'), '/providers/Microsoft.ManagedIdentity/Identities/default'), '2015-08-31-PREVIEW').tenantId]",
                                        "objectId": "[reference(concat('Microsoft.Web/sites/', variables('functionAppName'), '/providers/Microsoft.ManagedIdentity/Identities/default'), '2015-08-31-PREVIEW').principalId]",
                                        "permissions": {
                                            "secrets": [
                                                "get"
                                            ]
                                        }
                                    }
                                ]
                            },
                            "resources": [
                                {
                                    "type": "secrets",
                                    "name": "[variables('storageConnectionStringName')]",
                                    //...
                                    "dependsOn": [
                                        "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                        "[resourceId('Microsoft.Storage/storageAccounts', variables('storageAccountName'))]"
                                    ],
                                    "properties": {
                                        "value": "[concat('DefaultEndpointsProtocol=https;AccountName=', variables('storageAccountName'), ';AccountKey=', listKeys(variables('storageAccountResourceId'),'2015-05-01-preview').key1)]"
                                    }
                                },
                                {
                                    "type": "secrets",
                                    "name": "[variables('appInsightsKeyName')]",
                                    //...
                                    "dependsOn": [
                                        "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                        "[resourceId('Microsoft.Insights/components', variables('appInsightsName'))]"
                                    ],
                                    "properties": {
                                        "value": "[reference(resourceId('microsoft.insights/components/', variables('appInsightsName')), '2015-05-01').InstrumentationKey]"
                                    }
                                }
                            ]
                        }
                    ]
                })

  impact 0.5
  tag nist: ['AU-11', 'CM-12', 'SI-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.1'] }]

  ref 'https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-3-manage-application-identities-securely-and-automatically'
  ref 'https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest'
  ref 'https://docs.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest'

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
