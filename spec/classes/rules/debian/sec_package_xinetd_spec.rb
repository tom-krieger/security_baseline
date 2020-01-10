require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_package_xinetd' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          srv_chargen: true,
          security_baseline: {
            packages_installed: {
              xinetd: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'xinetd package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('xinetd')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('xinetd-pkg')
        else
          is_expected.not_to contain_package('xinetd')
          is_expected.to contain_echo('xinetd-pkg')
            .with(
              'message'  => 'xinetd package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
