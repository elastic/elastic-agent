#!/usr/bin/env groovy
@Library('apm@current') _

pipeline {
  agent none
  environment {
    REPO = 'elastic-agent'
    BASE_DIR = "src/github.com/elastic/${env.REPO}"
    SLACK_CHANNEL = '#elastic-agent'
    NOTIFY_TO = 'package+beats-contrib@elastic.co'
    JOB_GCS_BUCKET = credentials('gcs-bucket')
    JOB_GCS_CREDENTIALS = 'fleet-ci-gcs-plugin'
    DOCKER_SECRET = 'secret/observability-team/ci/docker-registry/prod'
    DOCKER_REGISTRY = 'docker.elastic.co'
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '100', artifactNumToKeepStr: '30', daysToKeepStr: '30'))
    timestamps()
    ansiColor('xterm')
    disableResume()
    durabilityHint('PERFORMANCE_OPTIMIZED')
    rateLimitBuilds(throttle: [count: 60, durationName: 'hour', userBoost: true])
    quietPeriod(10)
  }
  triggers {
    // disable upstream trigger on a PR basis
    upstream("elastic-agent/elastic-agent-mbp/${ env.JOB_BASE_NAME.startsWith('PR-') ? 'none' : env.JOB_BASE_NAME }")
  }
  stages {
    stage('Filter build') {
      agent { label 'ubuntu-20 && immutable' }
      when {
        beforeAgent true
        anyOf {
          triggeredBy cause: "IssueCommentCause"
          expression {
            def ret = isUserTrigger() || isUpstreamTrigger()
            if(!ret){
              currentBuild.result = 'NOT_BUILT'
              currentBuild.description = "The build has been skipped"
              currentBuild.displayName = "#${BUILD_NUMBER}-(Skipped)"
              echo("the build has been skipped due the trigger is a branch scan and the allowed ones are manual, GitHub comment, and upstream job")
            }
            return ret
          }
        }
      }
      environment {
        PATH = "${env.PATH}:${env.WORKSPACE}/bin"
        HOME = "${env.WORKSPACE}"
      }
      stages {
        stage('Checkout') {
          options { skipDefaultCheckout() }
          steps {
            pipelineManager([ cancelPreviousRunningBuilds: [ when: 'PR' ] ])
            deleteDir()
            gitCheckout(basedir: "${BASE_DIR}", githubNotifyFirstTimeContributor: false,
                        shallow: false, reference: "/var/lib/jenkins/.git-references/${REPO}.git")
            stash allowEmpty: true, name: 'source', useDefaultExcludes: false
            // set environment variables globally since they are used afterwards but GIT_BASE_COMMIT won't
            // be available until gitCheckout is executed.
            setEnvVar('URI_SUFFIX', "commits/${env.GIT_BASE_COMMIT}")
            // JOB_GCS_BUCKET contains the bucket and some folders, let's build the folder structure
            setEnvVar('PATH_PREFIX', "${JOB_GCS_BUCKET.contains('/') ? JOB_GCS_BUCKET.substring(JOB_GCS_BUCKET.indexOf('/') + 1) + '/' + env.URI_SUFFIX : env.URI_SUFFIX}")
            //TODO : uncomment
            //setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))
            setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))
          }
        }
        stage('Package') {
          options { skipDefaultCheckout() }
          steps {
            echo 'Done as part of the main pipeline'
          }
        }
        stage('DRA') {
          // The Unified Release process keeps moving branches as soon as a new
          // minor version is created, therefore old release branches won't be able
          // to use the release manager as their definition is removed.
          when {
            expression { return env.IS_BRANCH_AVAILABLE == "true" }
          }
          steps {
            googleStorageDownload(bucketUri: "gs://${JOB_GCS_BUCKET}/${URI_SUFFIX}/*",
                                  credentialsId: "${JOB_GCS_CREDENTIALS}",
                                  localDirectory: "${BASE_DIR}/build/distributions",
                                  pathPrefix: env.PATH_PREFIX)
            dir("${BASE_DIR}") {
              withMageEnv() {
                sh(label: 'create dependencies file', script: 'make release-manager-dependencies-snapshot')
              }
              dockerLogin(secret: env.DOCKER_SECRET, registry: env.DOCKER_REGISTRY)
              script {
                getVaultSecret.readSecretWrapper {
                  sh(label: 'release-manager.sh', script: '.ci/scripts/release-manager.sh')
                }
              }
            }
          }
        }
      }
    }
  }
  post {
    cleanup {
      notifyBuildResult(prComment: false)
    }
    failure {
      echo 'disabled'
    // notifyStatus(slackStatus: 'danger', subject: "[${env.REPO}@${env.BRANCH_NAME}] DRA failed", body: "Build: (<${env.RUN_DISPLAY_URL}|here>)")
    }
  }
}

def notifyStatus(def args = [:]) {
  releaseNotification(slackChannel: "${env.SLACK_CHANNEL}",
                      slackColor: args.slackStatus,
                      slackCredentialsId: 'jenkins-slack-integration-token',
                      to: "${env.NOTIFY_TO}",
                      subject: args.subject,
                      body: args.body)
}
