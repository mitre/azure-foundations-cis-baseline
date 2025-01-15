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
    tag nist: ['RA-5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8' => ['7.5','7.6'] }]

    describe 'benchmark' do
        skip 'configure'
    end
end