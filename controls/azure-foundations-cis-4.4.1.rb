control 'azure-foundations-cis-1.1.1' do
    title 'title here'
    desc "mandatory description"

    desc 'rationale',
        "mandatory rationale description"

    desc 'check',
       "mandatory check description"

    desc 'fix',
       "optional fix description"

    desc 'other descriptions',
        "check aws baseline for examples"

    impact 0.5
    ref 'mandatory reference link'
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    describe 'benchmark' do
        skip 'configure'
    end
end