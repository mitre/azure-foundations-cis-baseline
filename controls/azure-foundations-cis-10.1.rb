control 'azure-foundations-cis-10.1' do
  title 'Ensure that Resource Locks are set for Mission-Critical Azure Resources'
  desc 'Resource Manager Locks provide a way for administrators to lock down Azure resources to prevent deletion of, or modifications to, a resource. These locks sit outside of the Role Based Access Controls (RBAC) hierarchy and, when applied, will place restrictions on the resource for all users. These locks are very useful when there is an important resource in a subscription that users should not be able to delete or change. Locks can help prevent accidental and malicious changes or deletion.'

  desc 'rationale',
       "As an administrator, it may be necessary to lock a subscription, resource group, or resource to prevent other users in the organization from accidentally deleting or modifying critical resources. The lock level can be set to to CanNotDelete or ReadOnly to achieve this purpose.
            • CanNotDelete means authorized users can still read and modify a resource, but they cannot delete the resource.
            • ReadOnly means authorized users can read a resource, but they cannot delete or update the resource. Applying this lock is similar to restricting all authorized users to the permissions granted by the Reader role."

  desc 'impact',
       'There can be unintended outcomes of locking a resource. Applying a lock to a parent service will cause it to be inherited by all resources within. Conversely, applying a lock to a resource may not apply to connected storage, leaving it unlocked. Please see the documentation for further information.'

  desc 'check',
       "Audit from Azure Portal
            1. Navigate to the specific Azure Resource or Resource Group
            2. Click on Locks
            3. Ensure the lock is defined with name and description, with type Read-only or Delete as appropriate.
        Audit from Azure CLI
            Review the list of all locks set currently:
                az lock list --resource-group <resourcegroupname> --resource-name <resourcename> --namespace <Namespace> --resource-type <type> --parent ""
        Audit From Powershell
            Run the following command to list all resources.
                Get-AzResource
            For each resource, run the following command to check for Resource Locks.
                Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource Type> -ResourceGroupName <Resource Group Name>
            Review the output of the Properties setting. Compliant settings will have the CanNotDelete or ReadOnly value."

  desc 'fix',
       "Remediate from Azure Portal
            1. Navigate to the specific Azure Resource or Resource Group
            2. For each mission critical resource, click on Locks
            3. Click Add
            4. Give the lock a name and a description, then select the type, Read-only or Delete as appropriate
            5. Click OK
        Remediate from Azure CLI
            To lock a resource, provide the name of the resource, its resource type, and its resource group name.
                az lock create --name <LockName> --lock-type <CanNotDelete/Read-only> --resource-group <resourceGroupName> --resource-name <resourceName> --resource-type <resourceType>
        Remediate From Powershell
            Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <Resource Type> -ResourceGroupName <Resource Group Name> -Locktype <CanNotDelete/Read-only>"

  impact 0.5
  tag nist: ['AC-3', 'AC-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3'] }]

  ref 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-lock-resources'
  ref 'https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-subscription-governance#azure-resource-locks'
  ref 'https://docs.microsoft.com/en-us/azure/governance/blueprints/concepts/resource-locking'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-4-limit-access-to-asset-management'

  resource_script = 'Get-AzResource | ConvertTo-Json'
  resource_output = powershell(resource_script).stdout.strip
  all_resources = json(content: resource_output).params

  only_if('N/A - No Resources found', impact: 0) do
    case all_resources
    when Array
      !all_resources.empty?
    when Hash
      !all_resources.empty?
    else
      false
    end
  end

  ensure_resource_locks_set_script = %(
        $ErrorActionPreference = "Stop"
        # Get all resources in the subscription
        $resources = Get-AzResource

        # Iterate over each resource
        foreach ($resource in $resources) {
            $resourceName = $resource.ResourceName
            $resourceType = $resource.ResourceType
            $resourceGroupName = $resource.ResourceGroupName

            # Get resource locks for the current resource
            $locks = Get-AzResourceLock -ResourceName $resourceName -ResourceType $resourceType -ResourceGroupName $resourceGroupName

            # Check if there are any locks
            if ($locks) {
                foreach ($lock in $locks) {
                    $lockName = $lock.Name
                    $lockLevel = $lock.LockLevel
                    # Check if the lock level is compliant
                    if ($lockLevel -eq "CanNotDelete" -or $lockLevel -eq "ReadOnly") {
                    }
                    else {
                        Write-Host "Resource: $resourceName (Type: $resourceType) in RG: $resourceGroupName"
                        Write-Host "  Does not have compliant lock setting."
                    }
                    Write-Host ""
                }
            } else {
                Write-Host "Resource: $resourceName (Type: $resourceType) in RG: $resourceGroupName"
                Write-Host "  No locks setting found."
            }
        }
  )

  pwsh_output = powershell(ensure_resource_locks_set_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure the number of resources with Properties setting not set to CanNotDelete or ReadOnly' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resources have issues: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
