require 'spec_helper'

describe 'security_baseline::rules::common::sec_ntalk' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_ntalk' => 'enabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'ntalk service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_ntalk' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'services_enabled' => {
                'srv_ntalk' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'ntalk service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('ntalk')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('ntalk')
          else
            is_expected.not_to contain_service('ntalk')
            is_expected.to contain_echo('ntalk')
              .with(
                'message'  => 'ntalk service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
