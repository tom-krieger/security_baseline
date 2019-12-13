require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_telnet_client' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              telnet: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'telnet client package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('telnet')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('telnet-client')
        else
          is_expected.not_to contain_package('telnet')
          is_expected.to contain_echo('telnet-client')
            .with(
              'message'  => 'telnet client package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
