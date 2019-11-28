# frozen_string_literal: true

# check a value and return a value depending on regex

def check_value_regex(val, search)
  if val.match?(%r{#{search}})
    true
  else
    false
  end
end
