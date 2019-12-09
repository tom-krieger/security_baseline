require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_x11_installed' do
  enforce_options.each do |enforce|
    context "Redhat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          security_baseline: {
            'x11-packages' => ['xorg-x11-xinit'],
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'x11-packages',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('xorg-x11-xinit')
            .with(
              'ensure' => 'purged',
            )

          is_expected.not_to contain_echo('x11-installed')
        else
          is_expected.not_to contain_package('xorg-x11-xinit')
          is_expected.to contain_echo('x11-installed')
            .with(
              'message'  => 'x11-packages',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
