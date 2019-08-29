# frozen_string_literal: true

# var_log_audit_partition.rb
# Makes sure that /var/log/audit is mounted

Facter.add('var_log_audit_partition') do
  confine :kernel => 'Linux'
  setcode 'mount | grep /var/log/audit'
end