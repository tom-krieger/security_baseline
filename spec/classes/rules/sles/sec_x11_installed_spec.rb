require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_x11_installed' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            'x11-packages' => ['xorg-x11-libs'],
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
          is_expected.to contain_package('xorg-x11-libs')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('x11-installed')
        else
          is_expected.not_to contain_package('xorg-x11-libs')
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
