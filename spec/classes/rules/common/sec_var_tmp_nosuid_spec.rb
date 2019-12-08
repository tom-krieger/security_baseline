require 'spec_helper'

describe 'security_baseline::rules::common::sec_var_tmp_nosuid' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'partitions' => {
              'var_tmp' => {
                'nodev' => false,
                'noexec' => false,
                'nosuid' => false,
                'partition' => '/var/tmp',
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'var_tmp nosuid',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('var-tmp-nosuid')
          .with(
            'message'  => 'var_tmp nosuid',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
