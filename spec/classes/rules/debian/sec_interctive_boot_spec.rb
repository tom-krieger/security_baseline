require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_interctive_boot' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce} and interactive boot" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'interactive_boot' => 'yes',
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'interactive boot',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_file_line('interactive-boot')
            .with(
              'ensure'             => 'present',
              'path'               => '/etc/sysconfig/boot',
              'line'               => 'PROMPT_FOR_CONFIRM="no"',
              'match'              => '^PROMPT_FOR_CONFIRM=',
              'append_on_no_match' => true,
            )

          is_expected.not_to contain_echo('interctive_boot')
        else
          is_expected.not_to contain_file_line('interactive-boot')
          is_expected.to contain_echo('interactive_boot')
            .with(
              'message'  => 'interactive boot',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "on Debian with enforce = #{enforce} and interactive boot not used" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'interactive_boot' => 'n/a',
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'interactive boot',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.not_to contain_echo('interctive_boot')
        is_expected.not_to contain_file_line('interactive-boot')
      }
    end
  end
end
