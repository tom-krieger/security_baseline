# frozen_string_literal: true

# issue.rb

Facter.add('issue_os') do
  confine :osfamily => 'RedHat'
  setcode 'egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue'
end