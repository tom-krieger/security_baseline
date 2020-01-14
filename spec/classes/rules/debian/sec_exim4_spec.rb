require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_exim4' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'packages_installed' => {
              'exim4' => true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'exim4 package',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_package('exim4')
            .with(
              'ensure' => 'absent',
            )
          is_expected.not_to contain_echo('exim4')
        else
          is_expected.not_to contain_package('exim4')
          is_expected.to contain_echo('exim4')
            .with(
              'message'  => 'exim4 package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
