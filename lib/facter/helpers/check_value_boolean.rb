# frozen_string_literal: true

# check a value and return a boolean value depending on conditions

def check_value_boolean(val, default)
  ret = if default == true
          false
        else
          true
        end

  if val.empty? || val.nil?
    default
  else
    ret
  end
end
