<script setup lang="ts">
import RegisterForm from '@/components/tideway/auth/RegisterForm.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <Card class="w-full max-w-md">
      <CardHeader class="text-center">
        <CardTitle class="text-2xl">Create an account</CardTitle>
        <CardDescription>Get started with your free account</CardDescription>
      </CardHeader>
      <CardContent>
        <RegisterForm />
        <div class="mt-4 text-center text-sm">
          <span class="text-muted-foreground">Already have an account? </span>
          <RouterLink to="/login" class="text-primary hover:underline">Sign in</RouterLink>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
