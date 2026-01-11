<script setup lang="ts">
import OrgSettings from '@/components/tideway/organizations/OrgSettings.vue'
import OrgSwitcher from '@/components/tideway/organizations/OrgSwitcher.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
</script>

<template>
  <div class="container max-w-4xl py-8">
    <div class="mb-8 flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold">Organization Settings</h1>
        <p class="text-muted-foreground">Manage your organization details and preferences</p>
      </div>
      <OrgSwitcher />
    </div>

    <Tabs default-value="general" class="space-y-4">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="members">Members</TabsTrigger>
      </TabsList>

      <TabsContent value="general">
        <Card>
          <CardHeader>
            <CardTitle>Organization Details</CardTitle>
            <CardDescription>Update your organization information</CardDescription>
          </CardHeader>
          <CardContent>
            <OrgSettings />
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="members">
        <Card>
          <CardHeader>
            <CardTitle>Team Members</CardTitle>
            <CardDescription>Manage who has access to this organization</CardDescription>
          </CardHeader>
          <CardContent>
            <RouterLink to="/settings/members" class="text-primary hover:underline">
              Go to Members page
            </RouterLink>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  </div>
</template>
