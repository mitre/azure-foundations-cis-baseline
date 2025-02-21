control 'azure-foundations-cis-8.11' do
  title 'Ensure Trusted Launch is enabled on Virtual Machines'
  desc 'When Secure Boot and vTPM are enabled together, they provide a strong foundation for protecting your VM from boot attacks. For example, if an attacker attempts to replace the bootloader with a malicious version, Secure Boot will prevent the VM from booting. If the attacker is able to bypass Secure Boot and install a malicious bootloader, vTPM can be used to detect the intrusion and alert you.'

  desc 'rationale',
       'Secure Boot and vTPM work together to protect your VM from a variety of boot attacks, including bootkits, rootkits, and firmware rootkits. Not enabling Trusted Launch in Azure VM can lead to increased vulnerability to rootkits and boot-level malware, reduced ability to detect and prevent unauthorized changes to the boot process, and a potential compromise of system integrity and data security.'

  desc 'impact',
       'Secure Boot and vTPM are not currently supported for Azure Generation 1 VMs.
      IMPORTANT: Before enabling Secure Boot and vTPM on a Generation 2 VM which does not already have both enabled, it is highly recommended to create a restore point of the VM prior to remediation.'

  desc 'check',
       "Audit from Azure Portal
          1. Go to Virtual Machines
          2. For each VM, under Settings, click on Configuration on the left blade
          3. Under Security Type, make sure security type is not standard and if it is Trusted Launch Virtual Machines then make sure Enable Secure Boot & Enable vTPM are checked
      Audit from Azure Policy
          If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
              • Policy ID: 97566dd7-78ae-4997-8b36-1c7bfe0d8121 - Name: '[Preview]: Secure Boot should be enabled on supported Windows virtual machines'"

  desc 'fix',
       "Remediate from Azure Portal
          1. Go to Virtual Machines
          2. For each VM, under Settings, click on Configuration on the left blade
          3. Under Security Type, select 'Trusted Launch Virtual Machines'
          4. Make sure Enable Secure Boot & Enable vTPM are checked
          5. Click on Apply.
      Note: Trusted launch on existing virtual machines (VMs) is currently not supported for Azure Generation 1 VMs"

  impact 0.5
  tag nist: ['CM-1', 'CM-2', 'CM-6', 'CM-7', 'CM-7(1)', 'CM-9', 'SA-3', 'SA-8', 'SA-10']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.1'] }]

  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm?tabs=portal'
  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm?tabs=portal#enable-trusted-launch-on-existing-vm'
  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch#secure-boot'

  describe 'Ensure Trusted Launch is enabled on Virtual Machines' do
    skip 'The check for this control needs to be done manually'
  end
end
