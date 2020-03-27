shared_examples 'os::centos::7' do
  puts 'CentOS 7 tests'
  include_examples 'common::1.1.1.1'
  include_examples 'common::1.1.1.2'
  include_examples 'common::1.1.1.3'
  include_examples 'common::1.1.1.4'
  include_examples 'common::1.1.1.5'
end
