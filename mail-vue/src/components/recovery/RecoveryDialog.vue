<template>
  <el-dialog v-model="visible" title="申请恢复账号" width="min(460px, 92vw)" @closed="reset">
    <p>请先联系 support@neutbo.com，告知要恢复的 Neutbo 邮箱，向客服索取恢复申请编号。</p>
    <p>填写申请编号后，验证码会发送到该账号已绑定的外部邮箱。验证完成后，请通知客服审核。</p>
    <div class="fields">
      <el-input v-model.trim="email" placeholder="要恢复的 Neutbo 邮箱" autocomplete="username" @input="clearChallenge" />
      <el-input v-model.trim="reference" placeholder="客服提供的 32 位申请编号" autocomplete="off" @input="clearChallenge" />
      <el-button :loading="sending" :disabled="countdown > 0 || verified" @click="send">{{ countdown ? `${countdown} 秒后可重发` : '发送验证码' }}</el-button>
      <el-input v-model.trim="code" placeholder="外部邮箱收到的 6 位验证码" maxlength="6" inputmode="numeric" autocomplete="one-time-code" />
      <el-button type="primary" :loading="verifying" :disabled="!challenge || verified" @click="verify">验证邮箱</el-button>
      <el-alert v-if="notice" :title="notice" type="info" :closable="false" show-icon />
      <el-alert v-if="verified" title="邮箱验证已完成，请联系原客服继续审核。" type="success" :closable="false" show-icon />
    </div>
  </el-dialog>
</template>

<script setup>
import {computed, onUnmounted, ref} from 'vue';
import {sendRecoveryCode,verifyRecoveryCode} from '@/request/recovery.js';

const props=defineProps({modelValue:Boolean});
const emit=defineEmits(['update:modelValue']);
const visible=computed({get:()=>props.modelValue,set:value=>emit('update:modelValue',value)});
const email=ref(''), reference=ref(''), code=ref(''), challenge=ref(''), notice=ref('');
const sending=ref(false), verifying=ref(false), verified=ref(false), countdown=ref(0);
let timer;
function clearChallenge(){challenge.value='';code.value='';verified.value=false;notice.value='';}
function reset(){clearInterval(timer);email.value='';reference.value='';countdown.value=0;clearChallenge();}
onUnmounted(()=>clearInterval(timer));
async function send(){
  if(!email.value || !/^[0-9a-f]{32}$/.test(reference.value)){ElMessage.warning('请填写邮箱和客服提供的申请编号');return;}
  sending.value=true;
  try {
    const data=await sendRecoveryCode(email.value);
    challenge.value=data.challenge;code.value='';
    notice.value='如果账号符合条件，验证码将发送至已绑定的外部邮箱。';
    countdown.value=60;clearInterval(timer);timer=setInterval(()=>{if(--countdown.value<=0)clearInterval(timer)},1000);
  } finally {sending.value=false;}
}
async function verify(){
  if(!/^\d{6}$/.test(code.value)){ElMessage.warning('请输入 6 位验证码');return;}
  verifying.value=true;
  try {await verifyRecoveryCode({email:email.value,code:code.value,challenge:challenge.value,supportReference:reference.value});verified.value=true;code.value='';notice.value='';}
  finally {verifying.value=false;}
}
</script>

<style scoped>
.fields{display:flex;flex-direction:column;gap:12px}.fields .el-button{margin:0}p{line-height:1.65;color:var(--el-text-color-regular)}
</style>
