#!/usr/bin/env groovy
@Library('apm@current') _

pipeline {
  agent none
  environment {
    REPO = 'elastic-agent'
    BASE_DIR = "src/github.com/elastic/${env.REPO}"
    // SLACK_CHANNEL = '#elastic-agent'
    SLACK_CHANNEL = '#observablt-bots'
    // NOTIFY_TO = 'beats-contrib+build-package@elastic.co'
    NOTIFY_TO = 'victor.martinez+elastic-agent@elastic.co'
    JOB_GCS_BUCKET = credentials('gcs-bucket')
    JOB_GCS_CREDENTIALS = 'fleet-ci-gcs-plugin'
    DOCKER_SECRET = 'secret/observability-team/ci/docker-registry/prod'
    DOCKER_REGISTRY = 'docker.elastic.co'
    DRA_OUTPUT = 'release-manager.out'
    DEPENDENCY_VERSION = "${params.DEPENDENCY_VERSION}"
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
  parameters {
    string(name: 'DEPENDENCY_VERSION', defaultValue: '', description: "Which versions of the agent's DRA dependencies are included in each build (if empty default behaviour).")
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
            dir("${BASE_DIR}"){
              setEnvVar('GO_VERSION', readFile(".go-version").trim())
            }
            //TODO : uncomment
            //setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))
            setEnvVar('IS_BRANCH_AVAILABLE', 'true')
            withMageEnv(version: "${env.GO_VERSION}"){
              dir("${BASE_DIR}"){
                setEnvVar('VERSION', sh(label: 'Get version', script: 'make get-version', returnStdout: true)?.trim())
              }
            }
          }
        }
        stage('Package') {
          options { skipDefaultCheckout() }
          steps {
            // Probably this should be done also here, so manual builds work too
            echo 'Done as part of the main pipeline'
          }
        }
        stage('DRA Snapshot') {
          options { skipDefaultCheckout() }
          // The Unified Release process keeps moving branches as soon as a new
          // minor version is created, therefore old release branches won't be able
          // to use the release manager as their definition is removed.
          when {
            expression { return env.IS_BRANCH_AVAILABLE == "true" }
          }
          environment {
            HOME = "${env.WORKSPACE}"
          }
          steps {
            runReleaseManager(type: 'snapshot', outputFile: env.DRA_OUTPUT)
          }
          post {
            failure {
              notifyStatus(analyse: true,
                           file: "${BASE_DIR}/${env.DRA_OUTPUT}",
                           subject: "[${env.REPO}@${env.BRANCH_NAME}] The Daily releasable artifact failed.",
                           body: 'Contact the Release Platform team [#platform-release].')
            }
          }
        }
        stage('DRA Staging') {
          options { skipDefaultCheckout() }
          // The Unified Release process keeps moving branches as soon as a new
          // minor version is created, therefore old release branches won't be able
          // to use the release manager as their definition is removed.
          when {
            expression { return env.IS_BRANCH_AVAILABLE == "true" }
            not { branch 'main' }
          }
          steps {
            echo 'TBD'
          }
        }
      }
    }
  }
  post {
    cleanup {
      notifyBuildResult(prComment: false)
    }
  }
}

def notifyStatus(def args = [:]) {
  def releaseManagerFile = args.get('file', '')
  def analyse = args.get('analyse', false)
  def subject = args.get('subject', '')
  def body = args.get('body', '')
  releaseManagerNotification(file: releaseManagerFile,
                             analyse: analyse,
                             slackChannel: "${env.SLACK_CHANNEL}",
                             slackColor: 'danger',
                             slackCredentialsId: 'jenkins-slack-integration-token',
                             to: "${env.NOTIFY_TO}",
                             subject: subject,
                             body: "Build: (<${env.RUN_DISPLAY_URL}|here>).\n ${body}")
}

def publishArtifacts(def args = [:]) {
  // Copy those files to another location with the sha commit to test them afterward.
  googleStorageUpload(bucket: getBucketLocation(args.type),
    credentialsId: "${JOB_GCS_CREDENTIALS}",
    pathPrefix: "${BASE_DIR}/build/distributions/",
    pattern: "${BASE_DIR}/build/distributions/**/*",
    sharedPublicly: true,
    showInline: true)
}

def runReleaseManager(def args = [:]) {
  deleteDir()
  unstash 'source'
  googleStorageDownload(bucketUri: "${getBucketLocation(args.type)}/*",
                        credentialsId: "${JOB_GCS_CREDENTIALS}",
                        localDirectory: "${BASE_DIR}/build/distributions",
                        pathPrefix: getBucketPathPrefix(args.type))
  dir("${BASE_DIR}") {
    def mageGoal = args.type.equals('staging') ? 'release-manager-dependencies-release' : 'release-manager-dependencies-snapshot'
    withMageEnv() {
      sh(label: 'create dependencies file', script: "make ${mageGoal}")
    }
    // help to download the latest release-manager docker image
    dockerLogin(secret: "${DOCKER_ELASTIC_SECRET}", registry: "${DOCKER_REGISTRY}")
    releaseManager(project: 'elastic-agent-shipper',
                   version: env.VERSION,
                   branch: env.BRANCH_NAME,
                   type: args.type,
                   artifactsFolder: 'build/distributions',
                   outputFile: args.outputFile)
  }
}

def getBucketLocation(type) {
  return "gs://${JOB_GCS_BUCKET}/${getBucketRelativeLocation(type)}"
}

def getBucketRelativeLocation(type) {
  def folder = type.equals('snapshot') ? 'commits' : type
  return "${env.REPO}/${folder}/${env.GIT_BASE_COMMIT}"
}

def getBucketPathPrefix(type) {
  // JOB_GCS_BUCKET contains the bucket and some folders,
  // let's build up the folder structure without the parent folder
  def relative = getBucketRelativeLocation(type)
  if (JOB_GCS_BUCKET.contains('/')) {
    return JOB_GCS_BUCKET.substring(JOB_GCS_BUCKET.indexOf('/') + 1) + '/' + relative
  }
  return relative
}
