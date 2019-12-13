require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_openbsd_inetd' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              'openbsd-inetd' => true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'openbsd-inetd package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('openbsd-inetd')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('openbsd-inetd')
        else
          is_expected.not_to contain_package('openbsd-inetd')
          is_expected.to contain_echo('openbsd-inetd')
            .with(
              'message'  => 'openbsd-inetd package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
