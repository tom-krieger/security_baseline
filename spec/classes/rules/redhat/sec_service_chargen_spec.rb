require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_chargen' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          srv_chargen: true,
          security_baseline: {
            xinetd_services: {
              srv_chargen: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive chargen',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('chargen-dgram')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('chargen-stream')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('chargen-service')
        else
          is_expected.not_to contain_service('chargen-dgram')
          is_expected.not_to contain_service('chargen-stream')
          is_expected.to contain_echo('chargen-service')
            .with(
              'message'  => 'servive chargen',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
