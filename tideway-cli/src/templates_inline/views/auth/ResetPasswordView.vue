<script setup lang="ts">
import ResetPassword from '@/components/auth/ResetPassword.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <Card class="w-full max-w-md">
      <CardHeader class="text-center">
        <CardTitle class="text-2xl">Set new password</CardTitle>
        <CardDescription>Choose a new password for your account</CardDescription>
      </CardHeader>
      <CardContent>
        <ResetPassword />
      </CardContent>
    </Card>
  </div>
</template>
