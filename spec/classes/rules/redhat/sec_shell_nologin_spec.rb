require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_shell_nologin' do
  enforce_options.each do |enforce|
    context "on Redhat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'accounts' => {
              'no_shell_nologin' => ['test1'],
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'no shell login',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('nologin test1')
            .with(
              'command' => 'usermod -s /sbin/nologin test1',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('nologin-shell')
        else
          is_expected.not_to contain_exec('nologin test1')
          is_expected.to contain_echo('nologin-shell')
            .with(
              'message'  => 'no shell login',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
