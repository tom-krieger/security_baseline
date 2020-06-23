shared_examples 'os::centos::8' do
  puts 'CentOS 8 tests' if ENV['DEBUG'] == '1'
  include_examples 'common::cramfs'
  include_examples 'common::vfat'
  include_examples 'common::squashfs'
  include_examples 'common::udf'
end
