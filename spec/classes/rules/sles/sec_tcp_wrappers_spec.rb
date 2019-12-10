require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_tcp_wrappers' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              tcp_wrappers: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'tcpd package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('tcpd')
            .with(
              'ensure' => 'installed',
            )

          is_expected.not_to contain_echo('tcpd')
        else
          is_expected.not_to contain_package('tcpd')
          is_expected.to contain_echo('tcpd')
            .with(
              'message'  => 'tcpd package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
