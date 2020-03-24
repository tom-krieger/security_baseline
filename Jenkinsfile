/*
 *
 * Jenkins Pipeline
 * Build svnam and create delivery artefacts and a docker container for tests
 *
 *
 * File: Jenkinsfile / development builds
 *
 */

@Library('joblib') _


params = [:]
params['branch'] = env.BRANCH_NAME
params['buildNode'] = 'pdk'

pdkPipeline.pdkPipeline(params)
