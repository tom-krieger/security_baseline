#!/bin/bash

pdk bundle install --quiet
pdk bundle exec rake 'litmus:provision[vagrant, centos/8]'
pdk bundle exec rake litmus:install_agent
pdk bundle exec bolt task run provision::fix_secure_path --modulepath spec/fixtures/modules -i inventory.yaml -t ssh_nodes
pdk bundle exec rake litmus:install_module
