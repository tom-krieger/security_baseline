#!/bin/bash

# install all needed gems locally
pdk bundle install --quiet

# fire up two docker containers
# bundle exec rake 'litmus:provision[docker, centos:7]'
# bundle exec rake 'litmus:provision[docker, ubuntu:18.04]'
# pdk bundle exec rake 'litmus:provision[vagrant, centos/7]'
# pdk bundle exec rake 'litmus:provision_list[dev_vagrant_all]'
# pdk bundle exec rake 'litmus:provision_list[dev_vagrant]'
pdk bundle exec rake 'litmus:provision[vagrant, centos/8]'

# install Puppet agent
pdk bundle exec rake litmus:install_agent

# vagrant workarroung for sudo secure_path
pdk bundle exec bolt task run provision::fix_secure_path --modulepath spec/fixtures/modules -i inventory.yaml -t ssh_nodes

# install Puppet module to test
pdk bundle exec rake litmus:install_module

# run tests in parallel with less output
pdk bundle exec rake litmus:acceptance:parallel

# run tests with more output
# TARGET_HOST=localhost:2222 pdk bundle exec rspec ./spec/acceptance --format d
# TARGET_HOST=localhost:2223 pdk bundle exec rspec ./spec/acceptance --format d

# TARGET_HOST=127.0.0.1:2222 pdk bundle exec rspec ./spec/acceptance --format d

# tear down the test environment
# pdk bundle exec rake litmus:tear_down

exit 0
