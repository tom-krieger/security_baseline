require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_tcp_wrappers' do
  enforce_options.each do |enforce|
    context "Redhat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              tcp_wrappers: false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'tcp_wrappers package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('tcp_wrappers')
            .with(
              'ensure' => 'present',
            )

          is_expected.not_to contain_echo('tcp_wrappers')
        else
          is_expected.not_to contain_package('tcp_wrappers')
          is_expected.to contain_echo('tcp_wrappers')
            .with(
              'message'  => 'tcp_wrappers package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
