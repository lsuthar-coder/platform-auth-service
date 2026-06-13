pipeline {
  agent any

  environment {
    IMAGE     = "ghcr.io/lsuthar-coder/auth-service:${GIT_COMMIT}"
    NAMESPACE = "platform"
  }

  stages {
    stage('Login to GHCR') {
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'ghcr-credentials',
          usernameVariable: 'USERNAME',
          passwordVariable: 'PASSWORD'
        )]) {
          sh 'echo $PASSWORD | docker login ghcr.io -u $USERNAME --password-stdin'
        }
      }
    }

    stage('Deploy to K8s') {
      steps {
        withCredentials([file(credentialsId: 'kubeconfig', variable: 'KUBECONFIG')]) {
          sh """
            kubectl set image deployment/auth-service \
              api=${IMAGE} \
              -n ${NAMESPACE} \
              --kubeconfig=\$KUBECONFIG

            kubectl rollout status deployment/auth-service \
              -n ${NAMESPACE} \
              --kubeconfig=\$KUBECONFIG \
              --timeout=120s
          """
        }
      }
    }
  }

  post {
    success {
      slackSend(
        channel: '#platform-alerts',
        color: 'good',
        message: "✅ auth-service deployed - ${GIT_COMMIT}"
      )
    }
    failure {
      slackSend(
        channel: '#platform-alerts',
        color: 'danger',
        message: "❌ auth-service deployment failed - ${GIT_COMMIT}"
      )
    }
  }
}