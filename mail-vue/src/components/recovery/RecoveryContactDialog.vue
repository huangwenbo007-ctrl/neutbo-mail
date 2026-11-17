<template>
  <el-dialog v-model="visible" title="设置恢复邮箱" width="min(460px, 92vw)" @open="load" @closed="reset">
    <p>设置一个你已经能收信的外部邮箱，例如 QQ、163 或 Gmail。申请恢复账号时，验证码会发到这里。</p>
    <p>设置时需要当前密码。只使用 Google 登录的账号，可使用已确认的 Google 邮箱申请恢复。</p>
    <el-alert v-if="status.configured" :title="`当前恢复邮箱：${status.maskedEmail}`" type="info" :closable="false" show-icon />
    <div class="fields">
      <el-input v-model.trim="email" placeholder="外部邮箱地址" autocomplete="email" @input="clearChallenge" />
      <el-input v-model="password" type="password" show-password placeholder="当前 Neutbo Mail 密码" autocomplete="current-password" />
      <el-button :loading="sending" :disabled="countdown > 0" @click="send">{{ countdown ? `${countdown} 秒后可重发` : '发送验证码' }}</el-button>
      <el-input v-model.trim="code" placeholder="外部邮箱收到的 6 位验证码" maxlength="6" inputmode="numeric" autocomplete="one-time-code" />
      <el-button type="primary" :disabled="!challenge" :loading="verifying" @click="verify">验证并保存</el-button>
      <el-alert v-if="notice" :title="notice" type="success" :closable="false" show-icon />
    </div>
  </el-dialog>
</template>
<script setup>
import {computed,onUnmounted,ref} from 'vue';
import {recoveryContactStatus,sendRecoveryContactCode,verifyRecoveryContactCode} from '@/request/recovery.js';
const props=defineProps({modelValue:Boolean});
const emit=defineEmits(['update:modelValue']);
const visible=computed({get:()=>props.modelValue,set:value=>emit('update:modelValue',value)});
const email=ref(''),password=ref(''),code=ref(''),challenge=ref(''),notice=ref('');
const status=ref({configured:false}),sending=ref(false),verifying=ref(false),countdown=ref(0);
let timer;
function clearChallenge(){challenge.value='';code.value='';notice.value='';}
function reset(){clearInterval(timer);email.value='';password.value='';countdown.value=0;status.value={configured:false};clearChallenge();}
onUnmounted(()=>clearInterval(timer));
async function load(){status.value=await recoveryContactStatus();}
async function send(){
  if(!email.value||!password.value){ElMessage.warning('请填写外部邮箱和当前密码');return;}
  sending.value=true;
  try{const result=await sendRecoveryContactCode(email.value,password.value);password.value='';challenge.value=result.challenge;code.value='';notice.value=`验证码已发送至 ${result.maskedEmail}`;countdown.value=60;clearInterval(timer);timer=setInterval(()=>{if(--countdown.value<=0)clearInterval(timer)},1000);}
  finally{password.value='';sending.value=false;}
}
async function verify(){
  if(!/^\d{6}$/.test(code.value)){ElMessage.warning('请输入 6 位验证码');return;}
  verifying.value=true;
  try{status.value=await verifyRecoveryContactCode(challenge.value,code.value);challenge.value='';code.value='';notice.value='恢复邮箱已验证并保存';}
  finally{verifying.value=false;}
}
</script>
<style scoped>
.fields{display:flex;flex-direction:column;gap:12px;margin-top:14px}.fields .el-button{margin:0}p{line-height:1.65;color:var(--el-text-color-regular)}
</style>
