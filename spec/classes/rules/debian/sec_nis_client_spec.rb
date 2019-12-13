require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_nis_client' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              nis: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nis package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('nis')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('nis-client')
        else
          is_expected.not_to contain_package('nis')
          is_expected.to contain_echo('nis-client')
            .with(
              'message'  => 'nis package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
