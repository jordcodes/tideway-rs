<script setup lang="ts">
import SubscriptionStatus from '@/components/billing/SubscriptionStatus.vue'
import InvoiceHistory from '@/components/billing/InvoiceHistory.vue'
import BillingPortalButton from '@/components/billing/BillingPortalButton.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
</script>

<template>
  <div class="container max-w-4xl py-8">
    <div class="mb-8">
      <h1 class="text-3xl font-bold">Billing</h1>
      <p class="text-muted-foreground">Manage your subscription and billing details</p>
    </div>

    <div class="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Subscription</CardTitle>
          <CardDescription>Your current plan and status</CardDescription>
        </CardHeader>
        <CardContent>
          <SubscriptionStatus />
        </CardContent>
      </Card>

      <Card>
        <CardHeader class="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Payment Method</CardTitle>
            <CardDescription>Manage your payment details</CardDescription>
          </div>
          <BillingPortalButton />
        </CardHeader>
      </Card>

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle>Invoice History</CardTitle>
          <CardDescription>View and download your past invoices</CardDescription>
        </CardHeader>
        <CardContent>
          <InvoiceHistory />
        </CardContent>
      </Card>
    </div>
  </div>
</template>
