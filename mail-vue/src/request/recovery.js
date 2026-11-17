import http from '@/axios/index.js';

export const sendRecoveryCode = email => http.post('/recovery/email/send', {email});
export const verifyRecoveryCode = body => http.post('/recovery/email/verify', body);
export const createRecoveryTicket = userId => http.post('/user/recovery/ticket', {userId});
export const recoveryStatus = userId => http.get('/user/recovery/status', {params:{userId}});
export const approveRecovery = (userId,supportReference) => http.post('/user/recovery/approve', {userId,supportReference});
export const recoveryContactStatus = () => http.get('/my/recovery-contact');
export const sendRecoveryContactCode = (email,password) => http.post('/my/recovery-contact/send', {email,password});
export const verifyRecoveryContactCode = (challenge,code) => http.post('/my/recovery-contact/verify', {challenge,code});
