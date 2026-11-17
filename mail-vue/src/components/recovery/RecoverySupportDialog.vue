<template>
  <el-dialog v-model="visible" title="账号恢复审核" width="min(520px, 92vw)" @open="load" @closed="reset">
    <p>申请账号：<strong>{{ user?.email }}</strong></p>
    <p>创建编号后，通过原有客服渠道交给申请人。申请人验证外部邮箱后，再核对并批准。</p>
    <el-button :loading="loading" :disabled="status.available" @click="create">创建申请编号</el-button>
    <div class="fields">
      <el-input v-model.trim="reference" placeholder="申请编号（创建后请交给申请人）" autocomplete="off" />
      <el-alert v-if="status.available" :title="status.verified ? '邮箱已验证，可核对后审核' : '等待申请人验证邮箱'" :type="status.verified ? 'success' : 'info'" :closable="false" show-icon />
      <el-alert v-else title="当前没有有效的恢复申请编号" type="info" :closable="false" show-icon />
      <div class="actions">
        <el-button :loading="loading" @click="load">刷新状态</el-button>
        <el-button type="primary" :loading="loading" :disabled="!status.verified || !/^[0-9a-f]{32}$/.test(reference)" @click="approve">确认恢复</el-button>
      </div>
      <div v-if="status.history?.length" class="history">
        <strong>最近操作</strong>
        <div v-for="(entry,index) in status.history" :key="index">{{ entry.action === 'approve' ? '批准恢复' : '创建编号' }} · {{ formatTime(entry.created_at) }} · 管理员 {{ entry.actor_user_id }}</div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup>
import {computed,ref} from 'vue';
import {createRecoveryTicket,recoveryStatus,approveRecovery} from '@/request/recovery.js';

const props=defineProps({modelValue:Boolean,user:Object});
const emit=defineEmits(['update:modelValue','restored']);
const visible=computed({get:()=>props.modelValue,set:value=>emit('update:modelValue',value)});
const reference=ref(''), loading=ref(false), status=ref({available:false,history:[]});
function reset(){reference.value='';status.value={available:false,history:[]};}
function formatTime(seconds){return new Date(seconds*1000).toLocaleString();}
async function load(){if(!props.user?.userId)return;loading.value=true;try{status.value=await recoveryStatus(props.user.userId);}finally{loading.value=false;}}
async function create(){loading.value=true;try{const result=await createRecoveryTicket(props.user.userId);reference.value=result.supportReference;status.value=await recoveryStatus(props.user.userId);}finally{loading.value=false;}}
async function approve(){
  try{await ElMessageBox.confirm(`确认恢复 ${props.user.email}？请先核对申请和邮箱验证状态。`,'确认恢复',{type:'warning'});}catch{return;}
  loading.value=true;
  try{await approveRecovery(props.user.userId,reference.value);ElMessage.success('账号已恢复');emit('restored');visible.value=false;}finally{loading.value=false;}
}
</script>

<style scoped>
.fields{display:flex;flex-direction:column;gap:12px;margin-top:12px}.actions{display:flex;gap:8px}.actions .el-button{margin:0}.history{font-size:13px;line-height:1.8;color:var(--el-text-color-secondary)}p{line-height:1.65;color:var(--el-text-color-regular)}
</style>
