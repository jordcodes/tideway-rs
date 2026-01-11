<script setup lang="ts">
import MfaVerify from '@/components/auth/MfaVerify.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <Card class="w-full max-w-md">
      <CardHeader class="text-center">
        <CardTitle class="text-2xl">Two-factor authentication</CardTitle>
        <CardDescription>Enter the code from your authenticator app</CardDescription>
      </CardHeader>
      <CardContent>
        <MfaVerify />
      </CardContent>
    </Card>
  </div>
</template>
