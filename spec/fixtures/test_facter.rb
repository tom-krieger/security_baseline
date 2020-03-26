#!/usr/bin/env ruby

require 'puppet'
require 'facter'

Puppet.initialize_settings

ORIG_FACTERLIB = ENV['FACTERLIB']
ENV['FACTERLIB'] = nil

Puppet.settings[:basemodulepath].split(':').each do |path|

  Dir.glob(path + "/**/lib/facter").map { |i| ENV['FACTERLIB'].nil? ? ENV['FACTERLIB'] = i : ENV['FACTERLIB'] += ':' + i }

end

# reload facter
Facter.clear

arg = ARGV[0]

puts Facter.value(arg.to_s)

ENV['FACTERLIB'] = ORIG_FACTERLIB
