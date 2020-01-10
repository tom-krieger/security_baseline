require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_access_control' do
  enforce_options.each do |enforce|
    context "on Dev´bian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            'apparmor' => {
              'bootloader' => false,
            },
            'access_control' => 'none',
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' =>  'neither apparmor nor selinux installed',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('apparmor')
            .with(
              'ensure' => 'installed',
            )
          is_expected.to contain_package('apparmor-utils')
            .with(
              'ensure' => 'installed',
            )

          is_expected.not_to contain_echo('apparmor-pkg')
        else
          is_expected.not_to contain_package('apparmor')
          is_expected.not_to contain_package('apparmor-utils')
          is_expected.to contain_echo('apparmor-pkg')
            .with(
              'message'  => 'neither apparmor nor selinux installed',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
