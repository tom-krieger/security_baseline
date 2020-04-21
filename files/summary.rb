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
percent = {}

counters['ok'] = 0
counters['fail'] = 0
counters['informational'] = 0
counters['unknown'] = 0
counters['error'] = 0
all_tests = 0

data = YAML.load_file(file)

data['security_baseline_findings'].each do |rule_name, rule_data|
  all_tests += 1
  if rule_data['scored'] == 'true'
    if rule_data['status'] == 'unknown'
      counters['unknown'] += 1
    elsif rule_data['status'] == 'fail'
      counters['fail'] += 1
    elsif rule_data['status'] == 'compliant'
      counters['ok'] += 1
    else
      counters['error'] += 1
    end
    summary[rule_name.to_s] = rule_data['status']
  else
    counters['informational'] += 1
  end
end

counters['num_tests'] = all_tests
counters['num_scored'] = all_tests - counters['informational']

if all_tests > 0
  percent['unknown'] = (counters['unknown'].to_f * 100 / all_tests.to_f).round(2)
  percent['fail'] = (counters['fail'].to_f * 100 / all_tests.to_f).round(2)
  percent['ok'] = (counters['ok'].to_f * 100 / all_tests.to_f).round(2)
  percent['error'] = (counters['error'].to_f * 100 / all_tests.to_f).round(2)
  percent['informational'] = (counters['informational'].to_f * 100 / all_tests.to_f).round(2)
else
  percent['unknown'] = 'n/a'
  percent['fail'] = 'n/a'
  percent['ok'] = 'n/a'
  percent['error'] = 'n/a'
  percent['informational'] = 'n/a'
end

results['tests'] = summary
results['counters'] = counters
results['percent'] = percent
output['security_baseline_summary'] = results

fh = File.open(out_file, 'w')
fh.write(output.to_yaml)
fh.write("\n")
fh.close

exit
