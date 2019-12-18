require 'spec_helper'

describe 'security_baseline::rules::common::sec_issue' do
  on_supported_os.each do |os, os_facts|
    context "on #{os} with content" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'issue' => {
              'os' => {
                'combined' => 666,
                'content' => 'htz',
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'issue os',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('issue-os')
          .with(
            'message'  => 'issue os',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end

    context "on #{os} without content" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'issue' => {
              'os' => {
                'combined' => 666,
                'content' => '',
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'issue os',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.not_to contain_echo('issue-os')
      }
    end
  end
end
