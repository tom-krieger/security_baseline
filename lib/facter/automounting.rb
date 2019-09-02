require 'facter/helpers/check_service_enabled'

# frozen_string_literal: true

# automounting.rb
# Check if automounting services are enabled

Facter.add('automounting') do
  confine :kernel => 'Linux'
  setcode do
    check_service_is_enabled('autofs')
  end
end