require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_interactive_boot' do
  enforce_options.each do |enforce|
    context "Redhat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'interactive_boot' => {
              'status' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'interactive boot settings',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.not_to contain_echo('interactive_boot')
          is_expected.to contain_file_line('interactive_boot')
            .with(
              'path'               => '/etc/sysconfig/init',
              'line'               => 'PROMPT=no',
              'match'              => '^PROMPT=',
              'append_on_no_match' => true,
            )
        else
          is_expected.not_to contain_file_line('interactive_boot')
          is_expected.to contain_echo('interactive_boot')
            .with(
              'message'  => 'interactive boot settings',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
