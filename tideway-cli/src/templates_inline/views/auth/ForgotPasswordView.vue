<script setup lang="ts">
import ForgotPassword from '@/components/tideway/auth/ForgotPassword.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <Card class="w-full max-w-md">
      <CardHeader class="text-center">
        <CardTitle class="text-2xl">Reset password</CardTitle>
        <CardDescription>Enter your email to receive a reset link</CardDescription>
      </CardHeader>
      <CardContent>
        <ForgotPassword />
        <div class="mt-4 text-center text-sm">
          <RouterLink to="/login" class="text-muted-foreground hover:underline">
            Back to login
          </RouterLink>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
