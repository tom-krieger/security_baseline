require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_daytime' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          srv_daytime: true,
          security_baseline: {
            xinetd_services: {
              srv_daytime: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive daytime',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('daytime-dgram')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('daytime-stream')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('daytime-service')
        else
          is_expected.not_to contain_service('daytime-dgram')
          is_expected.not_to contain_service('daytime-stream')
          is_expected.to contain_echo('daytime-service')
            .with(
              'message'  => 'servive daytime',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
