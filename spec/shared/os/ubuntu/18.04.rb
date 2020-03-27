
shared_examples 'os::ubuntu::18.04' do
    puts 'Ubuntu tests'
    include_examples 'common::1.1.1.1'
    include_examples 'common::1.1.1.2'
    include_examples 'common::1.1.1.3'
  end
  