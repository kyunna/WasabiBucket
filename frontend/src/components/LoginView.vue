<template>
    <div class="login-container">
      <el-card class="login-card">
        <template #header>
          <h2>로그인</h2>
        </template>
        <el-form :model="loginForm" @submit.prevent="handleLogin">
          <el-form-item label="Username">
            <el-input v-model="loginForm.username" />
          </el-form-item>
          <el-form-item label="Password">
            <el-input v-model="loginForm.password" type="password" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="loading">
              로그인
            </el-button>
          </el-form-item>
        </el-form>
      </el-card>
    </div>
  </template>
  
  <script>
  import { ref } from 'vue'
  import { useRouter } from 'vue-router'
  import { ElMessage } from 'element-plus'
  import { CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider'
  
  export default {
    name: 'LoginView',
    setup() {
      const router = useRouter()
      const loading = ref(false)
      const loginForm = ref({
        username: '',
        password: ''
      })
  
      const handleLogin = async () => {
        loading.value = true
        
        const client = new CognitoIdentityProviderClient({
          region: 'ap-northeast-2'
        })
  
        try {
          const command = new InitiateAuthCommand({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: process.env.VUE_APP_COGNITO_CLIENT_ID,
            AuthParameters: {
              USERNAME: loginForm.value.username,
              PASSWORD: loginForm.value.password
            }
          })
  
          const response = await client.send(command)
          localStorage.setItem('accessToken', response.AuthenticationResult.AccessToken)
          localStorage.setItem('idToken', response.AuthenticationResult.IdToken)
          router.push('/')
        } catch (error) {
          console.error('Login error:', error)
          ElMessage.error('로그인에 실패했습니다.')
        } finally {
          loading.value = false
        }
      }
  
      return {
        loginForm,
        loading,
        handleLogin
      }
    }
  }
  </script>
  
  <style scoped>
  .login-container {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }
  
  .login-card {
    width: 100%;
    max-width: 400px;
  }
  </style>