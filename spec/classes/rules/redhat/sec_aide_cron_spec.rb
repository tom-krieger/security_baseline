require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_aide_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'aide' => {
              'version' =>  '6.1.2',
              'status' => 'installed',
            }
          }
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'aide cron',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_file('/etc/cron.d/aide.cron')
          .with(
            'ensure' => 'file',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          )
      end
    end
  end
end
