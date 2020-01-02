require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_talk' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          srv_echo: true,
          security_baseline: {
            xinetd_services: {
              srv_echo: true,
              srv_talk: true,
            },
            servicves_enabled: {
              srv_talk: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive talk',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('talk')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('talk-service')
        else
          is_expected.not_to contain_service('talk')
          is_expected.to contain_echo('talk-service')
            .with(
              'message'  => 'servive talk',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
