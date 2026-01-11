<script setup lang="ts">
import MemberList from '@/components/organizations/MemberList.vue'
import InviteMember from '@/components/organizations/InviteMember.vue'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { ref } from 'vue'

const showInviteDialog = ref(false)
</script>

<template>
  <div class="container max-w-4xl py-8">
    <div class="mb-8 flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold">Team Members</h1>
        <p class="text-muted-foreground">Manage your organization's team</p>
      </div>

      <Dialog v-model:open="showInviteDialog">
        <DialogTrigger as-child>
          <Button>Invite Member</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Invite a team member</DialogTitle>
            <DialogDescription>
              Send an invitation to join your organization
            </DialogDescription>
          </DialogHeader>
          <InviteMember @success="showInviteDialog = false" />
        </DialogContent>
      </Dialog>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>Current Members</CardTitle>
        <CardDescription>People with access to this organization</CardDescription>
      </CardHeader>
      <CardContent>
        <MemberList />
      </CardContent>
    </Card>
  </div>
</template>
