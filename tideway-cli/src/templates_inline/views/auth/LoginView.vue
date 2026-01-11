<script setup lang="ts">
import LoginForm from '@/components/auth/LoginForm.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <Card class="w-full max-w-md">
      <CardHeader class="text-center">
        <CardTitle class="text-2xl">Welcome back</CardTitle>
        <CardDescription>Sign in to your account</CardDescription>
      </CardHeader>
      <CardContent>
        <LoginForm />
        <div class="mt-4 text-center text-sm">
          <span class="text-muted-foreground">Don't have an account? </span>
          <RouterLink to="/register" class="text-primary hover:underline">Sign up</RouterLink>
        </div>
        <div class="mt-2 text-center">
          <RouterLink to="/forgot-password" class="text-sm text-muted-foreground hover:underline">
            Forgot your password?
          </RouterLink>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
