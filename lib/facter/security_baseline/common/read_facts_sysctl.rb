# frozen_string_literal: true

# get facts about sysctl settings

def read_facts_sysctl(values)
  sysctl = {}

  values.each do |key|
    sysctl[key] = read_sysctl_value(key)
  end

  sysctl
end
