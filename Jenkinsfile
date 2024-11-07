pipeline {
    agent any

    tools {
        jdk 'jdk17' 
        maven 'maven'
    }

    environment {
        SCANNER_HOME = tool 'sonar-scanner'
        AWS_REGION = 'ap-south-1'
        ECR_REGISTRY = '836759839628.dkr.ecr.ap-south-1.amazonaws.com'
        ECR_REPOSITORY = 'jenkins/dockerimage'
        IMAGE_TAG = "${ECR_REGISTRY}/${ECR_REPOSITORY}:${env.BUILD_NUMBER}"
    }

    parameters {
        choice(
            name: 'SCAN_TYPE',
            choices: ['Baseline', 'API', 'FULL'],
            description: 'Select the type of ZAP scan you want to run.'
        )
    }

    stages {
        stage('Unit Test') {
            steps {
                sh "mvn test"
            }
        }

        stage('SonarQube SAST Analysis') {
            steps {
                withSonarQubeEnv('sonar-scanner') {
                    sh '''
                    $SCANNER_HOME/bin/sonar-scanner -Dsonar.projectKey=petclinic \
                    -Dsonar.java.binaries=. -Dsonar.coverage.exclusions=**/test/** \
                    -Dsonar.coverage.minimumCoverage=80 -Dsonar.issue.severity=HIGH \
                    -Dsonar.security.hotspots=true
                    '''
                }
            }
        }

        stage('OWASP Dependency-Check') {
            steps {
                dependencyCheck additionalArguments: '--scan ./ --format ALL', 
                                odcInstallation: 'dp', 
                                stopBuild: true
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }

        stage('Build Test') {
            steps {
                sh 'mvn clean package'
            }
        }

        stage('Lint Dockerfile with Hadolint') {
            steps {
                script {
                    sh 'docker run --rm -i hadolint/hadolint < Dockerfile > hadolint_report.txt'
                    archiveArtifacts artifacts: 'hadolint_report.txt', allowEmptyArchive: true
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t $IMAGE_TAG ."
            }
        }

        stage('Trivy Scan') {
            steps {
                script {
                    sh 'trivy image --severity HIGH,CRITICAL --format table $IMAGE_TAG > trivy-report.txt'
                    sh 'libreoffice --headless --convert-to pdf trivy-report.txt --outdir .'
                    archiveArtifacts artifacts: 'trivy-report.pdf', allowEmptyArchive: false
                }
            }
        }

        stage('OWASP ZAP Scan') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        def zapScript
                        def reportFile
                        if (params.SCAN_TYPE == 'Baseline') {
                            zapScript = 'zap-baseline.py'
                            reportFile = 'zap_baseline_report.html'
                        } else if (params.SCAN_TYPE == 'API') {
                            zapScript = 'zap-api-scan.py'
                            reportFile = 'zap_api_report.html'
                        } else if (params.SCAN_TYPE == 'FULL') {
                            zapScript = 'zap-full-scan.py'
                            reportFile = 'zap_full_report.html'
                        }
                        
                        def status = sh(script: '''
                        docker run -v $PWD:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
                        ''' + zapScript + ''' -t http://petclinic.jonathanjo.great-site.net > ''' + reportFile, returnStatus: true)
                        
                        archiveArtifacts artifacts: '*.html', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Push Docker Image to ECR') {
            steps {
                withCredentials([aws(credentialsId: 'aws-credentials', region: AWS_REGION)]) {
                    sh """
                        aws ecr get-login-password --region $AWS_REGION | \
                        docker login --username AWS --password-stdin $ECR_REGISTRY
                    """
                    sh "docker push $IMAGE_TAG"
                }
            }
        }
    }

   post {
        success {
            slackNotify("SUCCESS")
        }
        failure {
            slackNotify("FAILURE")
        }
        unstable {
            slackNotify("UNSTABLE")
        }
        always {
            script {
                def jobName = env.JOB_NAME
                def buildNumber = env.BUILD_NUMBER
                def buildUrl = env.BUILD_URL
                def pipelineStatus = currentBuild.result ?: 'UNKNOWN'
                def bannerColor = (pipelineStatus == 'SUCCESS') ? 'green' : 'red'
                
                def commitId = env.GIT_COMMIT ?: 'N/A'
                def triggeredBy = currentBuild.getBuildCauses().collect { cause -> cause.userId ?: 'Automated Trigger' }.join(", ")
                
                def body = """<html>
                                <body>
                                    <div style="border: 4px solid ${bannerColor}; padding: 10px;">
                                        <h2>${jobName} - Build ${buildNumber}</h2>
                                        <div style="background-color: ${bannerColor}; padding: 10px;">
                                            <h3 style="color: white;">Pipeline Status: ${pipelineStatus.toUpperCase()}</h3>
                                        </div>
                                        <p><strong>Build URL:</strong> <a href="${buildUrl}">${buildUrl}</a></p>
                                        <p><strong>Commit ID:</strong> ${commitId}</p>
                                        <p><strong>Triggered By:</strong> ${triggeredBy}</p>
                                    </div>
                                </body>
                              </html>"""

                emailext (
                    subject: "${jobName} - Build ${buildNumber} - ${pipelineStatus.toUpperCase()}",
                    body: body,
                    to: 'jonathanjonathanjo10@gmail.com',
                    from: 'jonathanjonathanjo10@gmail.com',
                    replyTo: 'jonathanjonathanjo10@gmail.com',
                    mimeType: 'text/html',
                    attachmentsPattern: '**/trivy-report.pdf, **/hadolint_report.html, **/zap_baseline_report.html, **/zap_api_report.html, **/zap_full_report.html'
                )
            }
        }
    }
}

// Function to send Slack notifications
def slackNotify(String status) {
    def triggerAuthor = currentBuild.changeSets.collectMany { changeSet ->
        changeSet.items.collect { it.author.fullName }
    }.join(', ') ?: "Unknown"

    slackSend (
        color: (status == "SUCCESS") ? "good" : ((status == "FAILURE") ? "danger" : "warning"),
        message: "*Build Status:* ${status}\n" +
                 "*Build Number:* ${env.BUILD_NUMBER}\n" +
                 "*Build Link:* <${env.BUILD_URL}|Click Here>\n" +
                 "*Triggered By:* ${triggerAuthor}"
    )
}
