pipeline {
  agent any

  environment {
    IMAGE = "ghcr.io/lsuthar-coder/auth-service:${GIT_COMMIT}"
    NAMESPACE = "platform"
  }

  stages {
    stage('Pull Latest Image') {
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'ghcr-credentials',
          usernameVariable: 'USERNAME',
          passwordVariable: 'PASSWORD'
        )]) {
          sh 'echo $PASSWORD | docker login ghcr.io -u $USERNAME --password-stdin'
          sh "docker pull ${IMAGE} || docker pull ghcr.io/lsuthar-coder/auth-service:latest"
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
              --kubeconfig=$KUBECONFIG

            kubectl rollout status deployment/auth-service \
              -n ${NAMESPACE} \
              --kubeconfig=$KUBECONFIG \
              --timeout=120s
          """
        }
      }
    }
  }

  post {
    success {
      slackSend(
        channel: '#deployments',
        color: 'good',
        message: "✅ auth-service deployed successfully - ${GIT_COMMIT}"
      )
    }
    failure {
      slackSend(
        channel: '#deployments',
        color: 'danger',
        message: "❌ auth-service deployment failed - ${GIT_COMMIT}"
      )
    }
  }
}