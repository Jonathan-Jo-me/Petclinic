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
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=petclinic \
                    -Dsonar.java.binaries=. \
                    -Dsonar.projectKey=devsecops \
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
                        dependencyCheck additionalArguments: '--scan ./ --format HTML --failOnCVSS 7', odcInstallation: 'dp'
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
                // Step 1: Lint the Dockerfile using Hadolint ( -Dsonar.qualitygate.wait=true \ )
                script {
                    // Run Hadolint Docker image and save output to a text file
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
                        // Define the script based on selected parameter
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

                        // Run the respective ZAP script using Docker
                        def status = sh(script: '''
                        docker run -v $PWD:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
                        ''' + zapScript + ''' -t https://www.example.com > ''' + reportFile, returnStatus: true)
                        
                       
                        archiveArtifacts artifacts: '*.html', allowEmptyArchive: true
                    }
                }
            }
        }
        
        
    }
}
