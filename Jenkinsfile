#!/usr/bin/env groovy

pipeline {

    agent {
        node {
            label 'linux'
        }
    }

    options {
        ansiColor('xterm')
        buildDiscarder(logRotator(artifactNumToKeepStr: '1'))
        compressBuildLog()
        parallelsAlwaysFailFast()
        retry(1)
        skipStagesAfterUnstable()
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
    }

    triggers {
        cron('H H(0-6) * * 1-5')
    }

    tools {
        maven 'M3'
        jdk '1.8'
    }

    environment {
        ITEXT7_LICENSEKEY = "${env.WORKSPACE}/license"
    }

    stages {
        stage('Compile') {
            steps {
                withMaven(jdk: '1.8', maven: 'M3') {
                    sh 'mvn compile test-compile'
                }
            }
        }
        stage('Static Code Analysis') {
            parallel {
                stage('Checkstyle') {
                    options {
                        timeout(time: 1, unit: 'MINUTES')
                    }
                    steps {
                        withMaven(jdk: '1.8', maven: 'M3') {
                            sh 'mvn checkstyle:checkstyle'
                        }
                    }
                    post {
                        always {
                            publishHTML(target: [
                                    allowMissing         : false,
                                    alwaysLinkToLastBuild: false,
                                    keepAll              : true,
                                    reportDir            : 'target/site',
                                    reportFiles          : 'checkstyle.html',
                                    reportName           : 'Checkstyle Report'
                            ])
                        }
                    }
                }
                stage('Findbugs') {
                    options {
                        timeout(time: 1, unit: 'MINUTES')
                    }
                    steps {
                        withMaven(jdk: '1.8', maven: 'M3') {
                            sh 'mvn findbugs:check'
                        }
                    }
                }
                stage('PMD') {
                    options {
                        timeout(time: 1, unit: 'MINUTES')
                    }
                    steps {
                        withMaven(jdk: '1.8', maven: 'M3') {
                            sh 'mvn pmd:pmd -Dpmd.analysisCache=true'
                        }
                    }
                }
            }
        }
        stage('Prepare test environment') {
            options {
                timeout(time: 1, unit: 'MINUTES')
            }
            steps {
                parallel (
                    "Typography" : {
                        dir ('license') {
                            sh 'git archive --format=tar --remote=ssh://git@git.itextsupport.com:7999/i7j/typography.git develop:src/test/resources/com/itextpdf/typography -- itextkey-typography.xml | tar -O -xf - > itextkey-typography.xml'
                        }
                    },
                    "Multiple Products" : {
                        dir ('license') {
                            sh 'git archive --format=tar --remote=ssh://git@git.itextsupport.com:7999/i7j/licensekey.git develop:src/test/resources/com/itextpdf/licensekey -- all-products.xml | tar -O -xf - > itextkey-multiple-products.xml'
                        }
                    }
                )
            }
        }
        stage('Run Tests') {
            parallel {
                stage('Surefire (Unit Tests)') {
                    options {
                        timeout(time: 1, unit: 'MINUTES')
                    }
                    steps {
                        withMaven(jdk: '1.8', maven: 'M3') {
                            sh 'mvn surefire:test -DgsExec=$(which gs) -DcompareExec=$(which compare) -Dmaven.test.skip=false -Dmaven.test.failure.ignore=false -Dmaven.javadoc.failOnError=false'
                        }
                    }
                    post {
                        always {
                            junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml'
                        }
                    }
                }
                stage('Failsafe (Integration Tests)') {
                    options {
                        timeout(time: 10, unit: 'MINUTES')
                    }
                    steps {
                        withMaven(jdk: '1.8', maven: 'M3') {
                            sh 'mvn failsafe:integration-test failsafe:verify -DgsExec=$(which gs) -DcompareExec=$(which compare) -Dmaven.test.skip=false -Dmaven.test.failure.ignore=false -Dmaven.javadoc.failOnError=false'
                        }
                    }
                    post {
                        always {
                            junit allowEmptyResults: true, testResults: 'target/failsafe-reports/*.xml'
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            echo 'One way or another, I have finished \uD83E\uDD16'
        }
        success {
            echo 'I succeeeded! \u263A'
        }
        unstable {
            echo 'I am unstable \uD83D\uDE2E'
        }
        failure {
            echo 'I failed \uD83D\uDCA9'
        }
        changed {
            echo 'Things were different before... \uD83E\uDD14'
        }
    }

}