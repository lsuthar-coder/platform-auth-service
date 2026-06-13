pipeline {
  agent any

  environment {
    IMAGE = "ghcr.io/lsuthar-coder/auth-service:${GIT_COMMIT}"
    NAMESPACE = "platform"
  }

  stages {
    stage('Deploy to K8s') {
  steps {
    withCredentials([
      sshUserPrivateKey(
        credentialsId: 'vps-ssh-key',
        keyFileVariable: 'SSH_KEY'
      )
    ]) {
      sh """
        ssh -i \$SSH_KEY -o StrictHostKeyChecking=no root@167.86.90.32 \
          "kubectl set image deployment/auth-service api=${IMAGE} -n platform && \
           kubectl rollout status deployment/auth-service -n platform --timeout=120s"
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