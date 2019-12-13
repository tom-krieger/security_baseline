require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_rsh_client' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              'rsh-client' => true,
              'rsh-redone-client' => true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsh package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('rsh-client')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_package('rsh-redone-client')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('rsh-client')
        else
          is_expected.not_to contain_package('rsh-client')
          is_expected.not_to contain_package('rsh-redone-client')
          is_expected.to contain_echo('rsh-client')
            .with(
              'message'  => 'rsh package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
