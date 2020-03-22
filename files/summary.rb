#!/usr/bin/env ruby

require 'yaml'
require 'pp'

if ARGV.length < 2
  puts 'Too few arguments'
  exit
end

file = ARGV[0]
out_file = ARGV[1]

output = {}
results = {}
counters = {}
summary = {}

counters['ok'] = 0
counters['fail'] = 0
counters['not_scored'] = 0
counters['unknown'] = 0
counters['unknown_state'] = 0

data = YAML.load_file(file)

data['security_baseline_findings'].each do |rule_name, rule_data|
  if rule_data['scored'] == 'true'
    if rule_data['status'] == 'compliant (no value)'
      counters['unknown'] += 1
    elsif rule_data['status'] == 'not compliant'
      counters['fail'] += 1
    elsif rule_data['status'] == 'compliant'
      counters['ok'] += 1
    else
      counters['unknown_state'] += 1
    end
    summary[rule_name.to_s] = rule_data['status']
  else
    counters['not_scored'] += 1
  end
end

results['tests'] = summary
results['counters'] = counters
output['security_baseline_summary'] = results

fh = File.open(out_file, 'w')
fh.write(output.to_yaml)
fh.write("\n")
fh.close

exit
