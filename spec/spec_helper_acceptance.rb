# frozen_string_literal: true

require 'puppet_litmus'
require 'spec_helper_acceptance_local' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_local.rb'))
require 'hiera-puppet-helper'

Dir['./spec/shared/**/*.rb'].sort.each { |f| require f }

include PuppetLitmus
PuppetLitmus.configure!
