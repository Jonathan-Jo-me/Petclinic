pipeline {
    agent any 

    tools {
        jdk 'jdk17' 
        maven 'maven'
    }

    environment {
        SCANNER_HOME = tool 'sonar-scanner'
        AWS_REGION = 'ap-south-1'                            // Set to your AWS region
        ECR_REGISTRY = '836759839628.dkr.ecr.ap-south-1.amazonaws.com'
        ECR_REPOSITORY = 'jenkins/dockerimage'               // Specify the full ECR repository path
        IMAGE_TAG = "${ECR_REGISTRY}/${ECR_REPOSITORY}:${env.BUILD_NUMBER}" 
    }

    parameters {
        // Active Choice parameter with 3 scan options
        choice(
            name: 'SCAN_TYPE',
            choices: ['Baseline', 'API', 'FULL'],
            description: 'Select the type of ZAP scan you want to run.'
        )
    }

    stages {
        stage(" Maven Test ") {
            steps {
                sh "mvn test"
            }
        }
        
        stage("Sonarqube Analysis") {
            steps {
                withSonarQubeEnv('sonar-scanner') {
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=sonar \
                    -Dsonar.java.binaries=. \
                    -Dsonar.projectKey=sonar \
                    -Dsonar.coverage.exclusions=**/test/** \
                    -Dsonar.coverage.minimumCoverage=80 \
                    -Dsonar.security.hotspots=true \
                    -Dsonar.issue.severity=HIGH
                    '''
                }
            }
        }
        
        stage('Owasp Dependency Check') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    timeout(time: 60, unit: 'MINUTES') {
                        dependencyCheck additionalArguments: '--scan ./ --format HTML', odcInstallation: 'dp'
                        dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                    }
                }
            }
        }
        
        stage("Maven Build") {
            steps {
                sh "mvn clean install"
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    echo "Building Docker image"
                    sh "docker build -t $IMAGE_TAG ."
                }
            }
        }
        
        stage('Login to ECR') {
            steps {
                withCredentials([aws(credentialsId: 'aws-credentials', region: AWS_REGION)]) {
                    script {
                        echo "Logging in to Amazon ECR"
                        sh """
                            aws ecr get-login-password --region $AWS_REGION | \
                            docker login --username AWS --password-stdin $ECR_REGISTRY
                        """
                    }
                }
            }
        }
        
        stage('Push Docker Image to ECR') {
            steps {
                script {
                    echo "Pushing Docker image to ECR"
                    sh "docker push $IMAGE_TAG"
                }
            }
        }
        
        stage('Lint Dockerfile') {
            steps {
                script {
                    sh 'docker run --rm -i hadolint/hadolint < Dockerfile > hadolint_report.html'
                    archiveArtifacts artifacts: 'hadolint_report.html', allowEmptyArchive: true
                }
            }
        }
        
        stage('Docker Image Vulnerability Scanning') {
            steps {
                script {
                    sh 'trivy image --severity HIGH,CRITICAL --format table $IMAGE_TAG > trivy-report.txt'
                    sh 'libreoffice --headless --convert-to pdf trivy-report.txt --outdir .'
                    archiveArtifacts artifacts: 'trivy-report.pdf', allowEmptyArchive: false
                }
            }
        }
        
        stage('ZAP Scan') {
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
                        ''' + zapScript + ''' -t http://ben.jonathanjo.great-site.net > ''' + reportFile, returnStatus: true)
                        
                        archiveArtifacts artifacts: '*.html', allowEmptyArchive: true
                    }
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
                    attachmentsPattern: '**/trivy-report.pdf, **/hadolint_report.html, **/zap_baseline_report.html'
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
